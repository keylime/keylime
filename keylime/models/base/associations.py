import copy
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional, Union, overload
from sqlalchemy import Column

from keylime.models.base.errors import AssociationTypeMismatch, AssociationValueInvalid
from keylime.models.base.associated_record_set import AssociatedRecordSet
from keylime.models.base.types.dictionary import Dictionary
from keylime.models.base.types.list import List
from keylime.models.base.db import db_manager

if TYPE_CHECKING:
    from keylime.models.base.basic_model import BasicModel
    from keylime.models.base.persistable_model import PersistableModel


class ModelAssociation(ABC):
    """A ModelAssociation represents a one-way association from one model to another. It cannot be instantiated directly
    and should be inherited from and customised for the specific type of association.

    As a Python descriptor [1], ModelAssociation allows associated records to be accessed from the parent record using
    dot notation. However, because the __get__ and __set__ methods need to differ depending on the association type (a
    "to-one" association should produce a single record whereas a "to-many" should return the whole
    AssociatedRecordSet), these are left to be defined by the subclass. Even so, protected getters and setters are
    provided by ModelAssociation to make these implementations as simple as possible and avoid duplication.

    [1] https://docs.python.org/3/howto/descriptor.html
    """

    def __init__(self, name: str, parent_model: type["BasicModel"], other_model: type["BasicModel"], inverse_of: Optional[str] = None) -> None:
        self._name: str = name
        self._private_member: str = "_" + name
        self._parent_model: type["BasicModel"] = parent_model
        self._other_model: type["BasicModel"] = other_model
        self._inverse_of: Optional[str] = inverse_of

    @abstractmethod
    def __get__(
        self, parent_record: "BasicModel", objtype: Optional[type["BasicModel"]] = None
    ) -> Union[AssociatedRecordSet, "BasicModel", "ModelAssociation", None]:
        pass

    def __delete__(self, parent_record: "BasicModel") -> None:
        self.get_record_set(parent_record).clear()

    def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "ModelAssociation", None]:
        if parent_record is None:
            return self

        record_set = self.get_record_set(parent_record)

        if len(record_set) == 1:
            (parent_record,) = record_set
            return parent_record

        return None

    def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "ModelAssociation", None]:
        if parent_record is None:
            return self

        return self.get_record_set(parent_record)

    def _set_one(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        if not isinstance(other_record, self.other_model):
            raise AssociationTypeMismatch(
                f"association '{self.name}' was given a value of type '{type(other_record).__name__}' which is not an "
                f"instance of '{self.other_model.__name__}' as required by the '{type(parent_record).__name__}' model"
            )

        record_set = self.get_record_set(parent_record)
        record_set.clear()
        record_set.add(other_record)

    def get_record_set(self, parent_record: "BasicModel") -> AssociatedRecordSet:
        if not hasattr(parent_record, self._private_member):
            setattr(parent_record, self._private_member, AssociatedRecordSet(parent_record, self))

        return getattr(parent_record, self._private_member)  # type: ignore[no-any-return]

    @property
    def name(self) -> str:
        return self._name
    
    @property
    def parent_model(self) -> type["BasicModel"]:
        return self._parent_model

    @property
    def other_model(self) -> type["BasicModel"]:
        return self._other_model
    
    @property
    def inverse_of(self) -> Optional[str]:
        if not self._inverse_of:
            # Get all associations which point from the associated model back to the parent model
            candidates = [
                assoc for assoc in self.other_model.associations.values()
                if assoc.other_model is self.parent_model
            ]

            # If there is only one such association in the associated model, the inverse association is unambiguous
            if len(candidates) == 1:
                self._inverse_of = candidates[0].name

        return self._inverse_of

    @property
    def inverse_association(self) -> Optional["ModelAssociation"]:
        if not self.inverse_of:
            return None

        return self.other_model.associations.get(self.inverse_of)

    @property
    @abstractmethod
    def preload(self) -> bool:
        pass

    @property
    @abstractmethod
    def to_one(self) -> bool:
        pass

    @property
    def to_many(self) -> bool:
        return not self.to_one


class EmbeddedAssociation(ModelAssociation):
    def __init__(
        self,
        name: str, 
        parent_model: type["BasicModel"], 
        other_model: type["BasicModel"],
        nullable: bool = False,
        inverse_of: Optional[str] = None
    ) -> None:
        self._nullable: bool = nullable
        super().__init__(name, parent_model, other_model, inverse_of)

    @property
    def preload(self) -> bool:
        return True

    @property
    def nullable(self) -> bool:
        return self._nullable


class EmbedsOneAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["BasicModel", "EmbedsOneAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        self._set_one(parent_record, other_record)

    def to_column(self, name=None) -> Optional[Column]:
        if not name:
            name = self.name

        db_type = Dictionary().get_db_type(db_manager.engine.dialect)
        return Column(name, db_type, nullable=self.nullable)

    @property
    def to_one(self) -> bool:
        return True

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "EmbedsOneAssociation", None]:
            ...


class EmbedsInlineAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["BasicModel", "EmbedsInlineAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        self._set_one(parent_record, other_record)

    @property
    def to_one(self) -> bool:
        return True

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "EmbedsInlineAssociation", None]:
            ...


class EmbedsManyAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["AssociatedRecordSet", "EmbedsManyAssociation", None]:
        return self._get_many(parent_record)

    def to_column(self, name=None) -> Optional[Column]:
        if not name:
            name = self.name

        db_type = List().get_db_type(db_manager.engine.dialect)
        return Column(name, db_type, nullable=self.nullable)

    @property
    def to_one(self) -> bool:
        return False

    if TYPE_CHECKING:

        def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "EmbedsManyAssociation", None]:
            ...


class EmbeddedInAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["BasicModel", "EmbedsOneAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        self._set_one(parent_record, other_record)

    @property
    def to_one(self) -> bool:
        return True

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "EmbedsOneAssociation", None]:
            ...


class EntityAssociation(ModelAssociation):
    """EntityAssociation extends ModelAssociation to provide additional functionality common to associations which
    map to a relationship between database entities.
    """

    def __init__(
        self,
        name: str,
        parent_model: type["PersistableModel"],
        other_model: type["PersistableModel"],
        inverse_of: Optional[str] = None,
        foreign_keys: Optional[tuple[str, ...]] = None,
        preload: bool = True,
    ) -> None:
        self._foreign_keys: Optional[str] = foreign_keys
        self._preload: bool = preload
        super().__init__(name, parent_model, other_model, inverse_of)

    def get_foreign_keys(self, search_inverse: bool = True) -> tuple[str, ...]:
        foreign_keys = self._foreign_keys or ()

        # If no foreign keys were declared for the association, see if is obtainable from the inverse association
        if not foreign_keys and search_inverse and self.inverse_association:
            foreign_keys = self.inverse_association.get_foreign_keys(search_inverse = False)

        return foreign_keys

    @property
    def foreign_keys(self) -> tuple[str, ...]:
        return self.get_foreign_keys()

    @property
    def preload(self) -> bool:
        return self._preload

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["PersistableModel", "EntityAssociation", None]:
            ...

        def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "EntityAssociation", None]:
            ...

        @property
        def other_model(self) -> type["PersistableModel"]:
            ...

        @property
        def inverse_association(self) -> Optional["EntityAssociation"]:
            ...


class HasOneAssociation(EntityAssociation):
    """A HasOneAssociation is an association between database-backed models which allows a record to be linked to
    one other. As this is achieved in the database engine with a foreign key in the associated record, it needs a
    corresponding BelongsToAssociation in the associated model.
    """

    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["PersistableModel", "HasOneAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "PersistableModel") -> None:
        self._set_one(parent_record, other_record)

    @property
    def to_one(self) -> bool:
        return True

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["PersistableModel", "HasOneAssociation", None]:
            ...


class HasManyAssociation(EntityAssociation):
    """A HasManyAssociation is an association between database-backed models which allows a record to be linked to
    an number of others. As this is achieved in the database engine with a foreign key in the associated records, it
    needs a corresponding BelongsToAssociation in the associated model.
    """

    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["AssociatedRecordSet", "HasManyAssociation", None]:
        return self._get_many(parent_record)

    @property
    def to_one(self) -> bool:
        return False

    if TYPE_CHECKING:

        def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "HasManyAssociation", None]:
            ...


class BelongsToAssociation(EntityAssociation):
    """A BelongsToAssociation is the inverse of a HasOneAssociation or HasManyAssociation. Like a HasOneAssociation, it
    links its parent record to, at most, one other record. In addition, it populates the parent record's foreign key
    field whenever the associated record changes.
    """

    def __init__(
        self,
        name: str,
        parent_model: type["PersistableModel"],
        other_model: type["PersistableModel"],
        nullable: bool = False,
        inverse_of: Optional[str] = None,
        foreign_keys: Optional[str] = None,
        preload: bool = True,
    ):
        self._nullable: bool = nullable
        super().__init__(name, parent_model, other_model, inverse_of, foreign_keys, preload)

    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["PersistableModel", "BelongsToAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "PersistableModel") -> None:
        if not type(other_record).id_field:
            raise AssociationValueInvalid(
                f"adding record to '{type(parent_record).__name__}.{self.name}' failed because "
                f"'{type(other_record).__name__}' does not have a single-field primary key"
            )

        # Create reference in record to the associated record
        self._set_one(parent_record, other_record)

        # Populate record's foreign key fields with the corresponding values from the associated record
        for field in type(parent_record).fields.values():
            if field.linked_association == self.name:
                foreign_value = getattr(other_record, field.linked_field)
                setattr(parent_record, field.name, foreign_value)

    def get_foreign_keys(self, search_inverse: bool = True) -> tuple[str, ...]:
        foreign_keys = super().get_foreign_keys(search_inverse)

        # If no foreign key was declared for the association (or the inverse association),
        # try to discover it from the model declaration
        if not foreign_keys:
            foreign_keys = (
                field.name
                for field in self.parent_model.fields.values()
                if field.linked_association == self.name
            )

        # If that fails, use the default
        if not foreign_keys:
            foreign_keys = (f"{self.name}_id")

        return foreign_keys

    @property
    def nullable(self) -> bool:
        return self._nullable

    @property
    def to_one(self) -> bool:
        return True

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["PersistableModel", "BelongsToAssociation", None]:
            ...

        @property
        def foreign_key(self) -> str:
            ...
