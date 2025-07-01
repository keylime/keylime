import re
from typing import Any, Optional, Pattern, TypeAlias

from sqlalchemy import Column, ForeignKey, ForeignKeyConstraint, Integer, Table, Text
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import RelationshipProperty, relationship

from keylime.models.base.associations import (
    EmbedsInlineAssociation,
    BelongsToAssociation,
    EntityAssociation,
    HasManyAssociation,
    HasOneAssociation,
)
from keylime.models.base.basic_model_meta import BasicModelMeta
from keylime.models.base.db import db_manager
from keylime.models.base.errors import SchemaInvalid
from keylime.models.base.field import ModelField


class PersistableModelMeta(BasicModelMeta):
    """PersistableModelMeta extends BasicModelMeta to additionally create those class members which are needed to map a
    model to an entity in a database. Refer to the documentation for BasicModel for an overview of the function of both
    these meta classes.

    Schema Helpers
    --------------

    The ``PersistableModelMeta`` class provides helper methods (macros) for declaring a model's schema, in addition to
    those provided by ``BasicModelMeta``. The helper methods specific to database-backed models are explained in the
    documentation for ``PersistableModel``.

    Changes to the Model Class Lifecycle
    ------------------------------------

    This section assumes familiarity with the lifecycle of a basic model (see ```BasicModelMeta``).

    When a new class is created which inherits from ``PersistableModel``, in addition to those class members which are
    created by ``BasicModelMeta``, a number of database-related class members are created and initialised. Most notably,
    an empty mapping class is created and stored as a member within the model class. This empty class will later be
    processed by the SQLAlchemy ORM and used to perform database queries.

    On calling ``Model.process_schema()``, a number of events take place in sequence. Schema helpers for declaring
    fields and associations create SQLAlchemy ``Column`` objects which are collected in the model class. Then, these are
    used to instantiate a new SQLAlchemy ``Table``, and a SQLAlchemy ``relationship`` is built for each association. The
    columns and relationships are given to SQLAlchemy to transform the empty mapping class into a class which resembles
    the database table with its various entity attributes, constraints, etc.

    The mapping class is used with the SQLAlchemy query API to save and retrieve records which creates an instance of
    the mapping class. Values are transparently copied into and out of this mapping class instance by
    ``PersistableModel`` at the appropriate times.
    """

    # pylint: disable=using-constant-test, no-value-for-parameter, unused-private-member, unsupported-membership-test, no-else-return

    DeclaredFieldType: TypeAlias = BasicModelMeta.DeclaredFieldType

    TABLE_NAME_REGEX: Pattern = re.compile(r"^[A-Za-z_]+[A-Za-z0-9_]*$")

    @staticmethod
    def __new_db_mapping(class_name: str) -> type:
        # Create empty Python class which will later be mapped to a database table
        db_mapping = type(class_name, (object,), {})

        # Because the dynamically-defined mapping class does not belong to a Python module in the usual sense, set
        # the module name to point to this method (where the definition of the mapping class occurs)
        setattr(db_mapping, "__module__", "PersistableModel.__new_db_mapping.<locals>")

        return db_mapping

    @staticmethod
    def __assoc_to_rship(association: "EntityAssociation", linked_fields) -> RelationshipProperty:
        lazy = "joined" if association.preload else "noload"

        return relationship(
            association.other_model.db_mapping,
            back_populates=association.inverse_of,
            lazy=lazy
        )

    def get_db_column_items(cls, embedded_in=None):
        items = {name: field for name, field in cls.fields.items() if field.persist}
        items |= cls.embeds_one_associations | cls.embeds_many_associations

        for sub_model in cls.sub_models:
            items |= sub_model.get_db_column_items()

        for embed in cls.embeds_inline_associations.values():
            items |= embed.other_model.get_db_column_items(embedded_in=embed)

        if embedded_in:
            for column_name in items.copy().keys():
                items[f"{embedded_in.name}__{column_name}"] = items.pop(column_name)

        return items

    @classmethod
    def __make_db_columns(mcs, cls) -> Table:
        columns = [item.to_column(name) for name, item in cls.get_db_column_items().items()]
        return columns

    @classmethod
    def __make_db_constraints(mcs, cls) -> Table:
        foreign_key_constraints = {}
        
        linked_fields = {
            name: item
            for name, item in cls.get_db_column_items().items()
            if isinstance(item, ModelField) and item.linked_association
        }

        for name, field in linked_fields.items():
            local_fields, linked_refs = foreign_key_constraints.get(field.linked_association, ([], []))
            local_fields.append(name)
            linked_refs.append(f"{field.linked_table}.{field.linked_field}")
            foreign_key_constraints[field.linked_association] = (local_fields, linked_refs)

        constraints = [ForeignKeyConstraint(*constraint_args) for constraint_args in foreign_key_constraints.values()]

        return constraints

    @classmethod
    def __make_db_table(mcs, cls) -> Table:
        db_table = Table(cls.table_name, db_manager.registry.metadata)

        for column in mcs.__make_db_columns(cls):
            db_table.append_column(column)

        for constraint in mcs.__make_db_constraints(cls):
            db_table.append_constraint(constraint)

        return db_table

    @classmethod
    def __make_relationships(mcs, cls) -> dict[str, relationship]:
        relationships = {}

        for name, assoc in cls.entity_associations.items():
            linked_fields = [field for field in cls.fields.values() if field.linked_association == assoc.name]
            relationships[name] = type(cls).__assoc_to_rship(assoc, linked_fields)

        return relationships

    @classmethod
    def _make_field(mcs, cls: "BasicModelMeta", name: str, data_type: DeclaredFieldType, **opts) -> ModelField:  # type: ignore[reportSelfClassParameterName]
        if not mcs._is_implementation(cls):
            raise TypeError(f"cannot create model field '{name}' on abstract class '{cls.__name__}'")

        nullable = opts.get("nullable", False)
        primary_key = opts.get("primary_key", False)
        column_kwargs = opts.get("column_kwargs", {})

        if primary_key and "_id" in [name for (name, _, _) in cls.schema_helpers_used]:
            raise SchemaInvalid(
                f"cannot create primary key using field '{name}' for model '{cls.__name__}' which already has a "
                f"single-field primary key defined using the 'cls._id(...)' schema helper"
            )

        if primary_key:
            mcs._getattr(cls, "__primary_key").append(name)
            column_kwargs = {**column_kwargs, "primary_key": True}

        field = super()._make_field(cls, name, data_type, **opts, column_kwargs=column_kwargs)

        return field

    def __new__(mcs, new_cls_name: str, bases: tuple[type, ...], attrs: dict[str, Any]) -> "PersistableModelMeta":
        cls = super().__new__(mcs, new_cls_name, bases, attrs)

        if mcs._is_implementation(cls):
            # Create new empty class to map to database once the schema is processed
            mapping_class = mcs.__new_db_mapping(f"{cls.__name__}Mapping")
            mcs._setattr(cls, "__db_mapping", mapping_class)
            mcs._setattr(cls, "__db_mapping_complete", False)
            # Initialise other attributes which can only be determined upon schema processing
            mcs._setattr(cls, "__table_name", None)
            mcs._setattr(cls, "__db_table", None)
            mcs._setattr(cls, "__primary_key", [])

        return cls  # type: ignore[reportReturnType, return-value]

    def _persist_as(cls, table_name: str) -> None:
        if not cls.schema_helpers_enabled:
            return

        if not re.match(ModelField.FIELD_NAME_REGEX, table_name):
            raise SchemaInvalid(f"'{table_name}' is an invalid name for a table")

        type(cls)._setattr(cls, "__table_name", table_name)
        type(cls)._log_schema_helper_use(cls, "_persist_as", table_name)

    def _id(cls, name: str, data_type: DeclaredFieldType = Integer) -> None:
        if not cls.schema_helpers_enabled:
            return

        if type(cls)._getattr(cls, "__primary_key"):
            raise SchemaInvalid(
                f"the cls._id({name}, {data_type}) helper cannot be used to create a primary key for model "
                f"'{cls.__name__}' which already has a primary key defined"
            )

        type(cls)._make_field(cls, name, data_type, primary_key=True)
        type(cls)._log_schema_helper_use(cls, "_id", name, data_type)

    def _field(cls, name: str, data_type: DeclaredFieldType, **opts) -> None:
        if not cls.schema_helpers_enabled:
            return

        if isinstance(data_type, Text):
            data_type = data_type.with_variant(LONGTEXT, "mysql")  # type: ignore[arg-type]
            data_type = data_type.with_variant(LONGTEXT, "mariadb")  # type: ignore[arg-type]

        type(cls)._make_field(cls, name, data_type, **opts)
        type(cls)._log_schema_helper_use(cls, "_field", name, data_type, **opts)

    def _virtual(cls, name: str, data_type: DeclaredFieldType, nullable: bool = False, render: bool = True) -> None:
        if cls.schema_helpers_enabled:
            type(cls)._make_field(cls, name, data_type, nullable=nullable, persist=False, render=render)
            type(cls)._log_schema_helper_use(cls, "_virtual", name, data_type, nullable, render=render)

    def _embeds_inline(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        association = EmbedsInlineAssociation(name, cls, *args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_embeds_inline", name, *args, **kwargs)

    def _has_one(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        association = HasOneAssociation(name, cls, *args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_has_one", name, *args, **kwargs)

    def _has_many(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        association = HasManyAssociation(name, cls, *args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_has_many", name, *args, **kwargs)

    def _belongs_to(cls, name: str, *args: Any, primary_key: bool = False, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        association = BelongsToAssociation(name, cls, *args, **kwargs)
        type(cls)._add_association(cls, association)

        if primary_key and "_id" in [name for (name, _, _) in cls.schema_helpers_used]:
            raise SchemaInvalid(
                f"cannot create primary key using field '{name}_id' for model '{cls.__name__}' which already has a "
                f"single-field primary key defined using the 'cls._id(...)' schema helper"
            )

        type(cls)._log_schema_helper_use(cls, "_belongs_to", name, *args, primary_key=primary_key, **kwargs)

    def process_schema(cls) -> None:
        # If schema has already been processed, do not process again
        if not cls.schema_awaiting_processing:
            return

        # Build the model's internal representation of the schema as defined
        super().process_schema()

        # If cls._persist_as(...) helper has not been called, skip creating DB mapping
        if not cls.table_name:
            return

        # If no primary key has been defined by the schema, create the default "id" primary key
        if not cls.primary_key:
            field = type(cls)._make_field(cls, "id", Integer, primary_key=True)

        # Prepare SQLAlchemy table object using the model's schema
        table = type(cls).__make_db_table(cls)
        setattr(cls, f"_{cls.__name__}__db_table", table)

        # Build SQLAlchemy Relationships from the associations defined by the model's schema
        relationships = type(cls).__make_relationships(cls)

        # Use SQLAlchemy to map the empty mapping class to the DB by providing the SQLAlchemy Table and Relationships
        db_manager.registry.map_imperatively(cls.db_mapping, cls.db_table, properties=relationships)  # type: ignore[reportArgumentType]

        # Also perform the DB mapping for each associated model to ensure this is done prior to attempting any queries
        for _, association in cls.associations.items():
            if association.other_model.schema_awaiting_processing:
                association.other_model.process_schema()

    @property
    def table_name(cls) -> Optional[str]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return type(cls)._getattr(cls, "__table_name")

    @property
    def db_mapping(cls) -> type:
        return type(cls)._getattr(cls, "__db_mapping")  # type: ignore[no-any-return]

    @property
    def db_mapping_complete(cls) -> bool:
        if not type(cls)._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema to map to database")

        return bool(type(cls)._getattr(cls, "__db_mapping_complete"))

    @property
    def db_table(cls) -> Table:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return type(cls)._getattr(cls, "__db_table")  # type: ignore[no-any-return]

    @property
    def primary_key(cls) -> list[str]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return list(type(cls)._getattr(cls, "__primary_key")).copy()

    @property
    def id_field(cls) -> Optional[ModelField]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        primary_key = type(cls)._getattr(cls, "__primary_key")
        field_count = len(primary_key)

        if field_count < 1 or field_count > 1:
            return None

        return cls.fields[primary_key[0]]  # pylint: disable=unsubscriptable-object

    @property
    def embeds_inline_associations(cls) -> dict[str, EmbedsInlineAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, EmbedsInlineAssociation)
        }

    @property
    def entity_associations(cls) -> dict[str, EntityAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, EntityAssociation)
        }

    @property
    def has_one_associations(cls) -> dict[str, HasOneAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, HasOneAssociation)
        }

    @property
    def has_many_associations(cls) -> dict[str, HasManyAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, HasManyAssociation)
        }

    @property
    def belongs_to_associations(cls) -> dict[str, BelongsToAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, BelongsToAssociation)
        }

    @property
    def persistable(cls) -> bool:
        return True

    @property
    def _repr_fields(cls) -> list[str]:
        field_names = super()._repr_fields
        field_names = [name for name in field_names if name not in cls.primary_key]
        field_names = cls.primary_key + field_names
        return field_names[:5]
