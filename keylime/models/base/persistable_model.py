from sqlalchemy import Column, ForeignKey, Integer, Table, Text
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import relationship

from keylime.models.base import BasicModel
from keylime.models.base.associations import BelongsToAssociation, HasManyAssociation, HasOneAssociation
from keylime.models.base.db import db_manager
from keylime.models.base.errors import FieldValueInvalid, QueryInvalid, SchemaInvalid


class PersistableModel(BasicModel):
    """PersistableModel extends the BasicModel class to provide additional functionality for saving and retrieving
    records to and from a database. Internally, a SQLAlchemy-mapped class is built dynamically from the schema
    defined by the implementing class and model change operations are mapped to their SQLAlchemy equivalent.
    Additionally, a query API is provided to fetch data from the database and properly instantiate records.

    For details on the schema, data validation and change management APIs, refer to the documentation for
    ``BasicModel``. You should subclass ``BasicModel`` directly in cases where you need an in-memory model that is
    not persisted to the database.
    """

    BUILT_IN_INST_ATTRS = [*BasicModel.BUILT_IN_INST_ATTRS, "db_mapping_inst", "_db_mapping_inst"]

    __db_mapping_processed = False

    @staticmethod
    def __new_db_mapping(class_name):
        # Create empty Python class which will later be mapped to a database table
        db_mapping = type(class_name, (object,), {})

        # Because the dynamically-defined mapping class does not belong to a Python module in the usual sense, set
        # the module name to point to this method (where the definition of the mapping class occurs)
        setattr(db_mapping, "__module__", "PersistableModel.__new_db_mapping.<locals>")

        return db_mapping

    @staticmethod
    def __make_db_table(table_name, columns):
        # Create empty SQLAlchemy Table which will used to map a class to the database
        db_table = Table(table_name, db_manager.registry.metadata)

        # Add the given columns to the table
        for column in columns:
            db_table.append_column(column)

        return db_table

    @staticmethod
    def __assoc_to_rship(association):
        lazy = "joined" if association.preload else "select"
        return relationship(association.other_model.__db_mapping, back_populates=association.inverse_of, lazy=lazy)

    @classmethod
    def _clear_model(cls):
        cls.__table_name = None
        cls.__db_mapping = None
        cls.__db_table = None
        cls.__db_columns = list()
        cls.__primary_key = set()
        cls.__id = None

        super()._clear_model()

    @classmethod
    def _process_schema(cls):
        # If schema has already been processed (and no changes have been made since), do not process again
        if cls._schema_processed:
            return

        # First, build the model's internal representation of the schema, as defined
        super()._process_schema()

        # Then, if no primary key has been defined by the schema, create the default "id" primary key
        if not cls.__id and not cls.__primary_key:
            field = cls._new_field("id", Integer, primary_key=True)
            cls.__id = field.name

        # Create new empty mapping class
        cls.__db_mapping = cls.__new_db_mapping(f"{cls.__name__}Mapping")
        # Prepare SQLAlchemy table using the model's schema
        cls.__db_table = cls.__make_db_table(cls.__table_name, cls.__db_columns)

        # Also process the schemas of all associated models to ensure their DB mapping classes are created prior
        # to actually performing the mapping via cls._process_db_mapping()
        for _, association in cls._associations.items():
            association.other_model._process_schema()

    @classmethod
    def _process_db_mapping(cls):
        # If the mapping class' attributes have already been mapped to their corresponding database entities,
        # do not repeat unless the schema has since changed
        if cls.__db_mapping_processed:
            return

        # If the model's internal representation of the schema is stale, reset and rebuild
        cls._process_schema()

        # Prevent DB mapping from being recreated unnecessarily
        cls.__db_mapping_processed = True

        # Check that a table name has been declared
        if not cls.__table_name:
            raise SchemaInvalid(
                f"peristable model '{cls.__name__}' must be given a database table name by calling "
                f"the 'cls._persist_as(table_name)' helper from the '_schema' method"
            )

        # Build SQLAlchemy Relationships from the associations defined by the model's schema
        relationships = {name: cls.__assoc_to_rship(association) for name, association in cls._associations.items()}
        # Use SQLAlchemy to map the empty mapping class to the DB by providing the SQLAlchemy Table and Relationships
        db_manager.registry.map_imperatively(cls.__db_mapping, cls.__db_table, properties=relationships)

        # Also perform the DB mapping for each associated model to ensure this is done prior to attempting any queries
        for _, association in cls._associations.items():
            association.other_model._process_db_mapping()

    @classmethod
    def _new_field(cls, name, type, nullable=False, primary_key=False, column_args=()):
        if primary_key and cls.__id:
            raise SchemaInvalid(
                f"cannot create primary key '{name}' for model '{cls.__name__}' which already has a primary key "
                f"defined using the 'cls._id({cls.__id}, {cls._fields[cls.__id].type})' helper"
            )

        if primary_key:
            cls.__primary_key.add(name)

        if not isinstance(column_args, tuple):
            column_args = (column_args,)

        field = super()._new_field(name, type, nullable)
        db_type = field.type.get_db_type(db_manager.engine.dialect)
        cls.__db_columns.append(Column(name, db_type, *column_args, nullable=nullable, primary_key=primary_key))

        return field

    @classmethod
    def _field(cls, name, type, nullable=False, primary_key=False):
        # TODO: Add validation

        if isinstance(type, Text):
            type = type.with_variant(LONGTEXT, "mysql").with_variant(LONGTEXT, "mariadb")

        cls._new_field(name, type, nullable, primary_key)

    @classmethod
    def _persist_as(cls, table_name):
        # TODO: Add validation
        cls.__table_name = table_name

    @classmethod
    def _id(cls, name, type=Integer):
        # TODO: Add validation

        if cls.__primary_key:
            raise SchemaInvalid(
                f"the cls.id({name}, {type}) helper cannot be used to create primary key '{name}' for model "
                f"'{cls.__name__}' which already has a primary key defined"
            )

        field = cls._new_field(name, type, primary_key=True)
        cls.__id = field.name

    @classmethod
    def _has_one(cls, name, *args, **kwargs):
        # TODO: Add validation
        args = [name, *args]
        association = HasOneAssociation(*args, **kwargs)

        cls._associations[name] = association
        setattr(cls, name, association)

    @classmethod
    def _has_many(cls, name, *args, **kwargs):
        # TODO: Add validation
        args = [name, *args]
        association = HasManyAssociation(*args, **kwargs)

        cls._associations[name] = association
        setattr(cls, name, association)

    @classmethod
    def _belongs_to(cls, name, *args, **kwargs):
        # TODO: Add validation
        args = [name, *args]
        association = BelongsToAssociation(*args, **kwargs)
        cls._associations[name] = association
        setattr(cls, name, association)

        # Create a new field for the foreign key
        other_model = association.other_model
        foreign_key = association.foreign_key
        is_primary_key = name in cls.__primary_key

        if len(other_model.primary_key) != 1:
            raise SchemaInvalid(
                f"model '{cls.__name__}' has a belongs_to association which points to a model with a composite "
                f"primary key (the associated model must have a primary key consisting of a single field)"
            )

        (other_model_id,) = other_model.primary_key
        foreign_key_type = other_model._fields[other_model_id].type

        cls._new_field(
            foreign_key,
            foreign_key_type,
            nullable=True,
            primary_key=is_primary_key,
            column_args=(ForeignKey(f"{other_model.__table_name}.{other_model_id}")),
        )

    @classmethod
    def all(cls, **filters):
        cls._process_db_mapping()

        filters = {name: value for name, value in filters.items() if value is not None}

        with db_manager.session_context() as session:
            results = session.query(cls.db_mapping).filter_by(**filters).all()
            results = [cls(mapping_inst) for mapping_inst in results]

        return results

    @classmethod
    def all_ids(cls, **filters):
        cls._process_db_mapping()

        if not cls.__id:
            raise QueryInvalid(f"model '{cls.__name__}' does not have an ID field")

        id_column = cls.db_table.columns[cls.__id]  # type: ignore
        filters = {name: value for name, value in filters.items() if value is not None}

        with db_manager.session_context() as session:
            results = session.query(id_column).filter_by(**filters).all()
            results = [row._asdict()[cls.__id] for row in results]

        return results

    @classmethod
    def get(cls, id=None, **filters):
        cls._process_db_mapping()

        if id:
            if not cls.__id:
                raise QueryInvalid(f"model '{cls.__name__}' does not have an ID field")
            else:
                filters[cls.__id] = id

        filters = {name: value for name, value in filters.items() if value is not None}

        with db_manager.session_context() as session:
            results = db_manager.session().query(cls.db_mapping).filter_by(**filters).one_or_none()

        if results:
            results = cls(results)
        else:
            results = None

        return results

    @classmethod
    def get_one(cls, **filters):
        cls._process_db_mapping()

        filters = {name: value for name, value in filters.items() if value is not None}

        with db_manager.session_context() as session:
            results = session.query(cls.db_mapping).filter_by(**filters).one_or_none()

        if results:
            results = cls(results)
        else:
            results = None

        return results

    @classmethod
    @property
    def _repr_fields(cls):
        field_names = super()._repr_fields
        field_names = [name for name in field_names if name not in cls.primary_key]
        field_names = list(cls.primary_key) + field_names
        return field_names[:5]

    @classmethod
    @property
    def persistable(cls):
        return True

    @classmethod
    @property
    def db_mapping(cls):
        cls._process_db_mapping()
        return cls.__db_mapping

    @classmethod
    @property
    def db_table(cls):
        cls._process_db_mapping()
        return cls.__db_table

    @classmethod
    @property
    def table_name(cls):
        cls._process_schema()
        return cls.__table_name

    @classmethod
    @property
    def primary_key(cls):
        cls._process_schema()
        return cls.__primary_key.copy()

    @classmethod
    @property
    def has_one_associations(cls):
        cls._process_schema()
        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, HasOneAssociation)
        }

    @classmethod
    @property
    def has_many_associations(cls):
        cls._process_schema()
        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, HasManyAssociation)
        }

    @classmethod
    @property
    def belongs_to_associations(cls):
        cls._process_schema()
        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, BelongsToAssociation)
        }

    def __init__(self, data={}, process_associations=True):
        self.__class__._process_db_mapping()

        if isinstance(data, self.__class__.db_mapping):  # type: ignore
            super().__init__({}, process_associations)
            self._init_from_mapping(data, process_associations)
        else:
            super().__init__(data, process_associations)

    def _init_from_mapping(self, mapping_inst, process_associations):
        self._db_mapping_inst = mapping_inst

        for name, field in self.__class__.fields.items():
            value = getattr(mapping_inst, name)
            self.change(name, field.type.db_load(value, db_manager.engine.dialect))

        if process_associations:
            for name, association in self.__class__.associations.items():
                association_mapping = getattr(mapping_inst, name)

                if association_mapping != None:
                    value = association.other_model(association_mapping, process_associations=False)
                    setattr(self, name, value)

        self._force_commit_changes()

    def _init_from_dict(self, data, process_associations):
        self._db_mapping_inst = self.__class__.db_mapping()  # type: ignore

        for name, value in data:
            self.change(name, value)
            setattr(self._db_mapping_inst, name, value)

        self._force_commit_changes()

    def change(self, name, value):
        super().change(name, value)

        field = self.__class__.fields[name]

        if not field.nullable and value is None:
            self._add_error(name, "cannot be null")

    def commit_changes(self):
        if not self.changes_valid:
            raise FieldValueInvalid(f"pending changes for model '{self.__class__.__name__}' have validation errors")

        for name, value in self._changes.items():
            self._record_values[name] = value

            field = self.__class__.fields[name]
            setattr(self._db_mapping_inst, name, field.type.db_dump(value, db_manager.engine.dialect))

        with db_manager.session_context() as session:
            session.add(self._db_mapping_inst)

        self.clear_changes()

    def delete(self):
        with db_manager.session_context() as session:
            session.delete(self._db_mapping_inst)
