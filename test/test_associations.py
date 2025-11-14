"""
Unit tests for keylime.models.base.associations module
"""

# pylint: disable=attribute-defined-outside-init,unnecessary-dunder-call
# Testing descriptor protocol requires dunder method calls
# Test models define attributes dynamically

import unittest

from sqlalchemy import Integer, create_engine
from sqlalchemy.orm import registry

from keylime.models.base import String, db_manager
from keylime.models.base.associations import (
    BelongsToAssociation,
    EmbedsManyAssociation,
    EmbedsOneAssociation,
    HasManyAssociation,
    HasOneAssociation,
)
from keylime.models.base.basic_model import BasicModel
from keylime.models.base.errors import AssociationTypeMismatch, AssociationValueInvalid
from keylime.models.base.persistable_model import PersistableModel


# Test models for testing associations
class ParentModel(PersistableModel):
    """Parent model for testing"""

    @classmethod
    def _schema(cls):
        cls._persist_as("parents")
        cls._id("id", Integer)
        cls._field("name", String(50))


class ChildModel(PersistableModel):
    """Child model for testing"""

    @classmethod
    def _schema(cls):
        cls._persist_as("children")
        cls._id("id", Integer)
        cls._field("name", String(50))
        cls._field("parent_id", Integer)


class EmbeddedModel(BasicModel):
    """Embedded model for testing (non-persistable)"""

    @classmethod
    def _schema(cls):
        cls._field("value", String(50))


class TestModelAssociationBase(unittest.TestCase):
    """Base test class for association tests"""

    @classmethod
    def setUpClass(cls):
        """Set up database schema once for all tests"""
        # pylint: disable=protected-access
        db_manager._engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        db_manager._registry = registry()
        db_manager._service = "test"
        # pylint: enable=protected-access

        # Process schemas
        ParentModel.process_schema()
        ChildModel.process_schema()
        EmbeddedModel.process_schema()

    def setUp(self):
        """Set up test database"""
        # Create tables
        ParentModel.db_table.create(db_manager.engine, checkfirst=True)
        ChildModel.db_table.create(db_manager.engine, checkfirst=True)

    def tearDown(self):
        """Clean up test database"""
        ChildModel.db_table.drop(db_manager.engine, checkfirst=True)
        ParentModel.db_table.drop(db_manager.engine, checkfirst=True)


class TestHasOneAssociation(TestModelAssociationBase):
    """Test cases for HasOneAssociation"""

    def test_has_one_initialization(self):
        """Test HasOneAssociation initialization"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel, inverse_of="parent")

        self.assertEqual(assoc.name, "child")
        self.assertEqual(assoc.parent_model, ParentModel)
        self.assertEqual(assoc.other_model, ChildModel)
        self.assertEqual(assoc.inverse_of, "parent")

    def test_has_one_to_one_property(self):
        """Test that HasOneAssociation.to_one returns True"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)

        self.assertTrue(assoc.to_one)
        self.assertFalse(assoc.to_many)

    def test_has_one_get_descriptor(self):
        """Test HasOneAssociation descriptor __get__"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)
        parent = ParentModel.empty()

        # Should return None when no associated record
        result = assoc.__get__(parent, None)
        self.assertIsNone(result)

    def test_has_one_set_descriptor(self):
        """Test HasOneAssociation descriptor __set__"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)
        parent = ParentModel.empty()
        child = ChildModel.empty()

        # Should set the associated record
        assoc.__set__(parent, child)  # type: ignore[arg-type]

        # Verify it was added to the record set
        record_set = assoc.get_record_set(parent)
        self.assertEqual(len(record_set), 1)
        self.assertIn(child, record_set)

    def test_has_one_preload_default(self):
        """Test that HasOneAssociation.preload defaults to True"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)

        self.assertTrue(assoc.preload)

    def test_has_one_preload_false(self):
        """Test HasOneAssociation with preload=False"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel, preload=False)

        self.assertFalse(assoc.preload)


class TestHasManyAssociation(TestModelAssociationBase):
    """Test cases for HasManyAssociation"""

    def test_has_many_initialization(self):
        """Test HasManyAssociation initialization"""
        assoc = HasManyAssociation("children", ParentModel, ChildModel)

        self.assertEqual(assoc.name, "children")
        self.assertEqual(assoc.parent_model, ParentModel)
        self.assertEqual(assoc.other_model, ChildModel)

    def test_has_many_to_one_property(self):
        """Test that HasManyAssociation.to_one returns False"""
        assoc = HasManyAssociation("children", ParentModel, ChildModel)

        self.assertFalse(assoc.to_one)
        self.assertTrue(assoc.to_many)

    def test_has_many_get_descriptor(self):
        """Test HasManyAssociation descriptor __get__"""
        assoc = HasManyAssociation("children", ParentModel, ChildModel)
        parent = ParentModel.empty()

        # Should return AssociatedRecordSet
        result = assoc.__get__(parent, None)
        self.assertIsNotNone(result)

        # Should be empty initially
        from keylime.models.base.associated_record_set import (  # pylint: disable=import-outside-toplevel
            AssociatedRecordSet,
        )

        self.assertIsInstance(result, AssociatedRecordSet)
        self.assertEqual(len(result), 0)  # type: ignore[arg-type]


class TestBelongsToAssociation(TestModelAssociationBase):
    """Test cases for BelongsToAssociation"""

    def test_belongs_to_initialization(self):
        """Test BelongsToAssociation initialization"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel, nullable=True)

        self.assertEqual(assoc.name, "parent")
        self.assertEqual(assoc.parent_model, ChildModel)
        self.assertEqual(assoc.other_model, ParentModel)
        self.assertTrue(assoc.nullable)

    def test_belongs_to_to_one_property(self):
        """Test that BelongsToAssociation.to_one returns True"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel)

        self.assertTrue(assoc.to_one)
        self.assertFalse(assoc.to_many)

    def test_belongs_to_nullable_default(self):
        """Test that BelongsToAssociation.nullable defaults to False"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel)

        self.assertFalse(assoc.nullable)

    def test_belongs_to_get_descriptor(self):
        """Test BelongsToAssociation descriptor __get__"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel)
        child = ChildModel.empty()

        # Should return None when no associated record
        result = assoc.__get__(child, None)
        self.assertIsNone(result)

    def test_belongs_to_set_descriptor_with_valid_record(self):
        """Test BelongsToAssociation descriptor __set__ with valid record"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel)
        child = ChildModel.empty()
        parent = ParentModel.empty()
        parent.id = 123

        # Should set the associated record
        assoc.__set__(child, parent)  # type: ignore[arg-type]

        # Verify it was added
        record_set = assoc.get_record_set(child)
        self.assertEqual(len(record_set), 1)
        self.assertIn(parent, record_set)

    def test_belongs_to_set_descriptor_with_none_nullable(self):
        """Test BelongsToAssociation descriptor __set__ with None when nullable"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel, nullable=True)
        child = ChildModel.empty()
        parent = ParentModel.empty()
        parent.id = 123

        # Add a parent first
        assoc.__set__(child, parent)  # type: ignore[arg-type]
        self.assertEqual(len(assoc.get_record_set(child)), 1)

        # Set to None should clear
        assoc.__set__(child, None)  # type: ignore[arg-type]
        self.assertEqual(len(assoc.get_record_set(child)), 0)

    def test_belongs_to_get_foreign_keys_default(self):
        """Test BelongsToAssociation.get_foreign_keys with default behavior"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel)

        # Should return default foreign key
        foreign_keys = assoc.get_foreign_keys()
        self.assertEqual(foreign_keys, ("parent_id",))

    def test_belongs_to_get_foreign_keys_explicit(self):
        """Test BelongsToAssociation.get_foreign_keys with explicit foreign keys"""
        assoc = BelongsToAssociation("parent", ChildModel, ParentModel, foreign_keys=("custom_id",))

        foreign_keys = assoc.get_foreign_keys()
        self.assertEqual(foreign_keys, ("custom_id",))


class TestEmbedsOneAssociation(TestModelAssociationBase):
    """Test cases for EmbedsOneAssociation"""

    def test_embeds_one_initialization(self):
        """Test EmbedsOneAssociation initialization"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel, nullable=True)

        self.assertEqual(assoc.name, "embedded")
        self.assertEqual(assoc.parent_model, ParentModel)
        self.assertEqual(assoc.other_model, EmbeddedModel)
        self.assertTrue(assoc.nullable)

    def test_embeds_one_to_one_property(self):
        """Test that EmbedsOneAssociation.to_one returns True"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel)

        self.assertTrue(assoc.to_one)
        self.assertFalse(assoc.to_many)

    def test_embeds_one_preload_property(self):
        """Test that EmbedsOneAssociation.preload returns True"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel)

        self.assertTrue(assoc.preload)

    def test_embeds_one_get_descriptor(self):
        """Test EmbedsOneAssociation descriptor __get__"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel)
        parent = ParentModel.empty()

        # Should return None when no embedded record
        result = assoc.__get__(parent, None)
        self.assertIsNone(result)

    def test_embeds_one_set_descriptor(self):
        """Test EmbedsOneAssociation descriptor __set__"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel)
        parent = ParentModel.empty()
        embedded = EmbeddedModel.empty()

        # Should set the embedded record
        assoc.__set__(parent, embedded)

        # Verify it was added
        record_set = assoc.get_record_set(parent)
        self.assertEqual(len(record_set), 1)
        self.assertIn(embedded, record_set)

    def test_embeds_one_set_descriptor_with_none_nullable(self):
        """Test EmbedsOneAssociation descriptor __set__ with None when nullable"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel, nullable=True)
        parent = ParentModel.empty()
        embedded = EmbeddedModel.empty()

        # Add an embedded record first
        assoc.__set__(parent, embedded)
        self.assertEqual(len(assoc.get_record_set(parent)), 1)

        # Set to None should clear
        assoc.__set__(parent, None)  # type: ignore[arg-type]
        self.assertEqual(len(assoc.get_record_set(parent)), 0)

    def test_embeds_one_to_column(self):
        """Test EmbedsOneAssociation.to_column() creates SQLAlchemy Column"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel)

        column = assoc.to_column()
        self.assertIsNotNone(column)
        self.assertEqual(column.name, "embedded")  # type: ignore[union-attr]

    def test_embeds_one_to_column_with_custom_name(self):
        """Test EmbedsOneAssociation.to_column() with custom name"""
        assoc = EmbedsOneAssociation("embedded", ParentModel, EmbeddedModel)

        column = assoc.to_column("custom_name")
        self.assertIsNotNone(column)
        self.assertEqual(column.name, "custom_name")  # type: ignore[union-attr]


class TestEmbedsManyAssociation(TestModelAssociationBase):
    """Test cases for EmbedsManyAssociation"""

    def test_embeds_many_initialization(self):
        """Test EmbedsManyAssociation initialization"""
        assoc = EmbedsManyAssociation("embedded_list", ParentModel, EmbeddedModel)

        self.assertEqual(assoc.name, "embedded_list")
        self.assertEqual(assoc.parent_model, ParentModel)
        self.assertEqual(assoc.other_model, EmbeddedModel)

    def test_embeds_many_to_one_property(self):
        """Test that EmbedsManyAssociation.to_one returns False"""
        assoc = EmbedsManyAssociation("embedded_list", ParentModel, EmbeddedModel)

        self.assertFalse(assoc.to_one)
        self.assertTrue(assoc.to_many)

    def test_embeds_many_preload_property(self):
        """Test that EmbedsManyAssociation.preload returns True"""
        assoc = EmbedsManyAssociation("embedded_list", ParentModel, EmbeddedModel)

        self.assertTrue(assoc.preload)

    def test_embeds_many_get_descriptor(self):
        """Test EmbedsManyAssociation descriptor __get__"""
        assoc = EmbedsManyAssociation("embedded_list", ParentModel, EmbeddedModel)
        parent = ParentModel.empty()

        # Should return AssociatedRecordSet
        result = assoc.__get__(parent, None)
        self.assertIsNotNone(result)

        from keylime.models.base.associated_record_set import (  # pylint: disable=import-outside-toplevel
            AssociatedRecordSet,
        )

        self.assertIsInstance(result, AssociatedRecordSet)

    def test_embeds_many_to_column(self):
        """Test EmbedsManyAssociation.to_column() creates SQLAlchemy Column"""
        assoc = EmbedsManyAssociation("embedded_list", ParentModel, EmbeddedModel)

        column = assoc.to_column()
        self.assertIsNotNone(column)
        self.assertEqual(column.name, "embedded_list")  # type: ignore[union-attr]


class TestEntityAssociation(TestModelAssociationBase):
    """Test cases for EntityAssociation base class"""

    def test_entity_association_initialization(self):
        """Test EntityAssociation initialization"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel, foreign_keys=("child_id",), preload=False)

        self.assertEqual(assoc.foreign_keys, ("child_id",))
        self.assertFalse(assoc.preload)

    def test_entity_association_get_foreign_keys_from_self(self):
        """Test EntityAssociation.get_foreign_keys() returns own foreign keys"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel, foreign_keys=("child_id",))

        foreign_keys = assoc.get_foreign_keys()
        self.assertEqual(foreign_keys, ("child_id",))

    def test_entity_association_get_foreign_keys_empty(self):
        """Test EntityAssociation.get_foreign_keys() with no foreign keys"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)

        foreign_keys = assoc.get_foreign_keys()
        self.assertEqual(foreign_keys, ())


class TestAssociationErrors(TestModelAssociationBase):
    """Test cases for association error handling"""

    def test_set_one_with_wrong_type_raises_error(self):
        """Test that setting wrong type raises AssociationTypeMismatch"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)
        parent = ParentModel.empty()
        wrong_type = ParentModel.empty()  # Wrong type!

        with self.assertRaises(AssociationTypeMismatch) as context:
            assoc.__set__(parent, wrong_type)  # type: ignore[arg-type]

        self.assertIn("not an instance of", str(context.exception))
        self.assertIn("ChildModel", str(context.exception))

    def test_belongs_to_set_without_id_field_raises_error(self):
        """Test that BelongsTo.set without id_field raises AssociationValueInvalid"""

        # Create a mock model without id_field
        class NoIdModel(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._persist_as("noid")
                cls._field("name", String(50), primary_key=True)  # pylint: disable=unexpected-keyword-arg
                cls._field("value", String(50), primary_key=True)  # pylint: disable=unexpected-keyword-arg

        NoIdModel.process_schema()

        assoc = BelongsToAssociation("no_id", ChildModel, NoIdModel)
        child = ChildModel.empty()
        no_id_record = NoIdModel.empty()

        with self.assertRaises(AssociationValueInvalid) as context:
            assoc.__set__(child, no_id_record)  # type: ignore[arg-type]  # pylint: disable=unexpected-keyword-arg

        self.assertIn("does not have a single-field primary key", str(context.exception))


class TestAssociationInverse(TestModelAssociationBase):
    """Test cases for inverse association functionality"""

    def test_inverse_of_explicit(self):
        """Test inverse_of when explicitly set"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel, inverse_of="parent")

        self.assertEqual(assoc.inverse_of, "parent")


class TestAssociationDescriptorProtocol(TestModelAssociationBase):
    """Test cases for descriptor protocol behavior"""

    def test_get_descriptor_with_none_returns_self(self):
        """Test that __get__ with None parent returns the association itself"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)

        # Calling with None should return the association
        result = assoc.__get__(None, ParentModel)  # type: ignore[arg-type]
        self.assertEqual(result, assoc)

    def test_delete_descriptor(self):
        """Test __delete__ clears the association"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)
        parent = ParentModel.empty()
        child = ChildModel.empty()

        # Add a child
        assoc.__set__(parent, child)  # type: ignore[arg-type]
        self.assertEqual(len(assoc.get_record_set(parent)), 1)

        # Delete should clear
        assoc.__delete__(parent)
        self.assertEqual(len(assoc.get_record_set(parent)), 0)

    def test_get_record_set_creates_lazy(self):
        """Test that get_record_set creates AssociatedRecordSet lazily"""
        assoc = HasOneAssociation("child", ParentModel, ChildModel)
        parent = ParentModel.empty()

        # First call should create the record set
        record_set1 = assoc.get_record_set(parent)
        self.assertIsNotNone(record_set1)

        # Second call should return same record set
        record_set2 = assoc.get_record_set(parent)
        self.assertIs(record_set1, record_set2)


if __name__ == "__main__":
    unittest.main()
