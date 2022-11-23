import time
from datetime import datetime
from typing import Dict, Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound
from tornado.locks import Event, Lock

from keylime import keylime_logging
from keylime.db.verifier_db import VerifierAllowlist

logger = keylime_logging.init_logging("allowlistdbproxy")


class AllowlistEntry:
    """AllowlistEntry represents a named allowlist in the DB"""

    session: Session

    update_lock: Lock
    last_update_check: float
    update_timeout: float

    allowlist_modified: datetime
    allowlist_id: int
    verifier_allowlist_db: VerifierAllowlist
    verifier_allowlist: VerifierAllowlist

    @staticmethod
    def from_db(session: Session, allowlist_id: int) -> Optional["AllowlistEntry"]:
        """Create an AllowlistEntry object from an entry in the DB"""
        try:
            verifier_allowlist_db = session.query(VerifierAllowlist).filter_by(id=allowlist_id).one()
        except NoResultFound:
            return None
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            return None
        return AllowlistEntry(session, allowlist_id, verifier_allowlist_db.modified, verifier_allowlist_db)

    def __init__(
        self,
        session: Session,
        allowlist_id: int,
        modified: datetime,
        verifier_allowlist_db: VerifierAllowlist,
        update_timeout: int = 0,
    ) -> None:
        """constructor"""
        self.session = session

        self.update_lock = Lock()
        self.last_update_check = time.monotonic()
        self.update_timeout = update_timeout

        self.allowlist_modified = modified
        self.allowlist_id = allowlist_id
        self.verifier_allowlist_db = verifier_allowlist_db
        self.verifier_allowlist = AllowlistEntry.__copy_verifier_allowlist(self.verifier_allowlist_db)

    @staticmethod
    def __copy_verifier_allowlist(tocopy: VerifierAllowlist) -> VerifierAllowlist:
        """Make a copy of the verifier_allowlist_db"""
        # This is the object we will give to the user; it's basically a read-only object without
        # access to the DB and should prevent that the user of the object sees changing fields
        # while we refresh() the object from the DB
        verifier_allowlist = VerifierAllowlist()
        verifier_allowlist.id = tocopy.id
        verifier_allowlist.name = tocopy.name
        verifier_allowlist.ima_policy = tocopy.ima_policy
        verifier_allowlist.tpm_policy = tocopy.tpm_policy
        verifier_allowlist.modified = tocopy.modified

        return verifier_allowlist

    def __was_modified(self) -> bool:
        """Check whether the modified timestamp of the allowlist in the DB has changed"""

        # Use raw SQL since formulating an SQLAlchemy statement may not work on older versions
        # This returns a ResultProxy on older versions, CursorResult on newer ones, the
        # fetchall() makes this a list of Row objects
        verifier_allowlist_list = self.session.execute(
            f"SELECT modified FROM allowlists WHERE id=={self.allowlist_id}"
        ).fetchall()
        if len(verifier_allowlist_list) == 0:
            raise NoResultFound()

        return verifier_allowlist_list[0].modified != self.allowlist_modified  # type: ignore

    async def check_update(self) -> bool:
        """Check for an update to the AllowlistEntry in the DB"""

        async with self.update_lock:
            now = time.monotonic()
            # We have to be really careful with this update_timeout. If attestation fails
            # and an update of the allowlist comes very quickly this update_timeout may
            # cause the new policy not to be loaded and cause an unexpected attestation
            # failure... it may be better to always poll the DB.
            if self.last_update_check + self.update_timeout < now:
                try:
                    if self.__was_modified():
                        self.session.refresh(self.verifier_allowlist_db)
                        self.allowlist_modified = self.verifier_allowlist_db.modified  # type: ignore

                        self.verifier_allowlist = AllowlistEntry.__copy_verifier_allowlist(self.verifier_allowlist_db)
                except NoResultFound:
                    return False
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                    return False

                self.last_update_check = now

            return True

    def is_expired(self, timeout: float) -> bool:
        """Check whether the object was not updated for 'timeout' seconds"""
        return self.last_update_check + timeout < time.monotonic()


class AllowlistDBProxy:
    """AllowlistDBProxy is used as a layer in front of the allowlist in the DB"""

    instance = None

    session: Session

    map_lock: Lock
    map: Dict[int, AllowlistEntry]

    purge_lock: Lock
    last_purge: float
    purge_timeout: float

    loader_map_lock: Lock
    loader_map: Dict[int, Event]

    @staticmethod
    def create_instance(session: Session) -> None:
        """Create the AllowlistDBProxy singleton"""
        if not AllowlistDBProxy.instance:
            AllowlistDBProxy.instance = AllowlistDBProxy(session)

    @staticmethod
    def get_instance() -> "AllowlistDBProxy":
        """Return the singleton AllowlistDBProxy"""
        assert AllowlistDBProxy.instance
        return AllowlistDBProxy.instance

    def __init__(self, session: Session, purge_timeout: int = 60) -> None:
        """constructor"""

        self.session = session

        self.map_lock = Lock()
        self.map = {}

        self.purge_lock = Lock()
        self.last_purge = 0
        self.purge_timeout = purge_timeout

        self.loader_map_lock = Lock()
        self.loader_map = {}

    async def __purge(self) -> None:
        """If purge timeout occurred remove all expired entries"""

        async with self.purge_lock:
            now = time.monotonic()
            if self.last_purge + self.purge_timeout < now:
                self.last_purge = now
            else:
                return

        async with self.map_lock:
            for allowlist_id in list(self.map.keys()):
                allowlist_entry = self.map[allowlist_id]
                if allowlist_entry.is_expired(self.purge_timeout):
                    del self.map[allowlist_id]

    async def __load_allowlist(self, allowlist_id: int) -> Optional[AllowlistEntry]:
        """Load an allowlist given its ID and put it into the map and return
        the loaded entry. Ensure that only one thread loads a specific entry
        and all other ones wanting to load the same entry wait for the first
        thread to have it loaded."""

        async with self.loader_map_lock:
            wait_event = self.loader_map.get(allowlist_id)
            if not wait_event:
                # First thread to load the entry
                notify_event = Event()
                self.loader_map[allowlist_id] = notify_event
            else:
                notify_event = None

        if wait_event:
            # Wait for other thread to notify us of loaded object
            wait_event.wait()
            async with self.map_lock:
                return self.map.get(allowlist_id)

        allowlist_entry = AllowlistEntry.from_db(self.session, allowlist_id)
        if allowlist_entry:
            async with self.map_lock:
                self.map[allowlist_id] = allowlist_entry

        async with self.loader_map_lock:
            del self.loader_map[allowlist_id]
            # Notify all waiters
            assert notify_event  # pyright
            notify_event.set()

        return allowlist_entry

    async def __get_allowlist(self, allowlist_id: int) -> Optional[AllowlistEntry]:
        """Get an allowlist given its ID"""

        async with self.map_lock:
            allowlist_entry = self.map.get(allowlist_id)

        if allowlist_entry:
            if not await allowlist_entry.check_update():
                # allowlist_entry likely disappeared from DB
                del self.map[allowlist_id]
                return None
            return allowlist_entry

        return await self.__load_allowlist(allowlist_id)

    async def get_allowlist(self, allowlist_id: int) -> Optional[AllowlistEntry]:
        """Get an allowlist given its ID; cleanup stale entries"""

        allowlist_entry = await self.__get_allowlist(allowlist_id)

        await self.__purge()

        return allowlist_entry
