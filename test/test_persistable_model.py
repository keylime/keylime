"""
Unit tests for keylime.models.base.persistable_model module

Tests the new query building functionality added in the push-attestation branch:
- _build_filter_criterion
- _build_sort_criterion
- _query with filters and sorting
- Enhanced get() with filters
- Enhanced all() with sorting
- Enhanced all_ids() with filters
- delete_all() batch operations
"""

import unittest

from sqlalchemy import asc, create_engine, desc
from sqlalchemy.orm import registry

from keylime.models.base import Integer, PersistableModel, String, db_manager
from keylime.models.base.errors import QueryInvalid


# Test model for persistable_model query functionality
class SampleItem(PersistableModel):
    """Simple test model to test PersistableModel query methods"""

    @classmethod
    def _schema(cls):
        cls._persist_as("sample_items")
        cls._id("id", Integer)
        cls._field("name", String(50))
        cls._field("category", String(50))
        cls._field("priority", Integer)


class TestPersistableModelQueries(unittest.TestCase):
    """Test cases for PersistableModel query methods"""

    @classmethod
    def setUpClass(cls):
        """Set up database schema once for all tests"""
        # pylint: disable=protected-access
        # Directly set up db_manager without using make_engine() which reads from config
        db_manager._engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        db_manager._registry = registry()
        db_manager._service = "test"
        # pylint: enable=protected-access

        # Process schema to create db_mapping
        SampleItem.process_schema()

    def setUp(self):
        """Set up test database and populate with test data"""
        # Create tables
        SampleItem.db_table.create(db_manager.engine, checkfirst=True)

        # Populate test data
        with db_manager.session_context() as session:
            items = [
                SampleItem.db_mapping(id=1, name="apple", category="fruit", priority=1),
                SampleItem.db_mapping(id=2, name="banana", category="fruit", priority=2),
                SampleItem.db_mapping(id=3, name="carrot", category="vegetable", priority=1),
                SampleItem.db_mapping(id=4, name="broccoli", category="vegetable", priority=3),
                SampleItem.db_mapping(id=5, name="orange", category="fruit", priority=2),
            ]
            for item in items:
                session.add(item)
            session.commit()

    def tearDown(self):
        """Clean up test database"""
        SampleItem.db_table.drop(db_manager.engine, checkfirst=True)

    def test_get_by_id(self):
        """Test get() method with ID parameter"""
        item = SampleItem.get(1)
        self.assertIsNotNone(item)
        # pylint: disable=no-member  # Dynamic ORM attributes
        self.assertEqual(item.id, 1)  # type: ignore[attr-defined]
        self.assertEqual(item.name, "apple")  # type: ignore[attr-defined]
        # pylint: enable=no-member

    def test_get_by_filter(self):
        """Test get() method with filter parameters"""
        item = SampleItem.get(name="banana")
        self.assertIsNotNone(item)
        # pylint: disable=no-member  # Dynamic ORM attributes
        self.assertEqual(item.id, 2)  # type: ignore[attr-defined]
        self.assertEqual(item.category, "fruit")  # type: ignore[attr-defined]
        # pylint: enable=no-member

    def test_get_with_multiple_filters(self):
        """Test get() method with multiple filter parameters"""
        item = SampleItem.get(category="vegetable", priority=3)
        self.assertIsNotNone(item)
        # pylint: disable=no-member  # Dynamic ORM attributes
        self.assertEqual(item.name, "broccoli")  # type: ignore[attr-defined]
        # pylint: enable=no-member

    def test_get_nonexistent(self):
        """Test get() returns None for nonexistent records"""
        item = SampleItem.get(id=999)
        self.assertIsNone(item)

    def test_all_with_filter(self):
        """Test all() method with filter parameter"""
        items = SampleItem.all(category="fruit")
        self.assertEqual(len(items), 3)
        # pylint: disable=no-member  # Dynamic ORM attributes
        categories = [item.category for item in items]  # type: ignore[attr-defined]
        # pylint: enable=no-member
        self.assertTrue(all(cat == "fruit" for cat in categories))

    def test_all_with_sorting_asc(self):
        """Test all() method with ascending sort"""
        items = SampleItem.all(category="fruit", sort_=asc("priority"))
        self.assertEqual(len(items), 3)
        # pylint: disable=no-member  # Dynamic ORM attributes
        priorities = [item.priority for item in items]  # type: ignore[attr-defined]
        # pylint: enable=no-member
        self.assertEqual(priorities, [1, 2, 2])

    def test_all_with_sorting_desc(self):
        """Test all() method with descending sort"""
        items = SampleItem.all(category="vegetable", sort_=desc("priority"))
        self.assertEqual(len(items), 2)
        # pylint: disable=no-member  # Dynamic ORM attributes
        priorities = [item.priority for item in items]  # type: ignore[attr-defined]
        # pylint: enable=no-member
        self.assertEqual(priorities, [3, 1])

    def test_all_with_multiple_sort_criteria(self):
        """Test all() method with multiple sort criteria"""
        items = SampleItem.all(sort_=(asc("priority"), asc("name")))
        self.assertEqual(len(items), 5)
        # Priority 1: apple, carrot (alphabetical)
        # Priority 2: banana, orange (alphabetical)
        # Priority 3: broccoli
        # pylint: disable=no-member  # Dynamic ORM attributes
        names = [item.name for item in items]  # type: ignore[attr-defined]
        # pylint: enable=no-member
        self.assertEqual(names, ["apple", "carrot", "banana", "orange", "broccoli"])

    def test_all_ids_with_filter(self):
        """Test all_ids() method with filter"""
        ids = SampleItem.all_ids(category="vegetable")
        self.assertEqual(len(ids), 2)
        self.assertIn(3, ids)
        self.assertIn(4, ids)

    def test_all_ids_with_sorting(self):
        """Test all_ids() method with sorting"""
        ids = SampleItem.all_ids(sort_=desc("id"))
        self.assertEqual(ids, [5, 4, 3, 2, 1])

    def test_build_filter_criterion_single_value(self):
        """Test _build_filter_criterion with single value"""
        # pylint: disable=protected-access  # Testing protected method
        criterion = SampleItem._build_filter_criterion("category", "fruit")
        # pylint: enable=protected-access
        self.assertIsNotNone(criterion)

    def test_build_filter_criterion_tuple_values(self):
        """Test _build_filter_criterion with tuple values (OR condition)"""
        # pylint: disable=protected-access  # Testing protected method
        criterion = SampleItem._build_filter_criterion("priority", (1, 2))
        # pylint: enable=protected-access
        self.assertIsNotNone(criterion)

        # Test that OR filter works correctly
        items = SampleItem.all(priority=(1, 2))
        self.assertEqual(len(items), 4)  # apple, banana, carrot, orange

    def test_build_filter_criterion_none_value(self):
        """Test _build_filter_criterion with None value returns empty list"""
        # pylint: disable=protected-access  # Testing protected method
        criterion = SampleItem._build_filter_criterion("category", None)
        # pylint: enable=protected-access
        self.assertEqual(criterion, [])

    def test_build_sort_criterion_asc(self):
        """Test _build_sort_criterion with ascending sort"""
        # pylint: disable=protected-access  # Testing protected method
        criterion = SampleItem._build_sort_criterion("name")
        # pylint: enable=protected-access
        self.assertIsNotNone(criterion)

    def test_build_sort_criterion_desc(self):
        """Test _build_sort_criterion with descending sort"""
        # pylint: disable=protected-access  # Testing protected method
        criterion = SampleItem._build_sort_criterion(desc("name"))
        # pylint: enable=protected-access
        self.assertIsNotNone(criterion)

    def test_delete_all_with_filter(self):
        """Test delete_all() method with filter"""
        # Delete all fruits
        SampleItem.delete_all(category="fruit")

        # Verify fruits are deleted
        remaining = SampleItem.all()
        self.assertEqual(len(remaining), 2)
        # pylint: disable=no-member  # Dynamic ORM attributes
        categories = [item.category for item in remaining]  # type: ignore[attr-defined]
        # pylint: enable=no-member
        self.assertTrue(all(cat == "vegetable" for cat in categories))

    def test_delete_all_without_filter(self):
        """Test delete_all() method without filter deletes all records"""
        SampleItem.delete_all()
        remaining = SampleItem.all()
        self.assertEqual(len(remaining), 0)

    def test_query_with_both_filters_and_expressions_raises_error(self):
        """Test that using both filters and expressions raises QueryInvalid"""
        with self.assertRaises(QueryInvalid) as context:
            # This should raise an error because we're mixing filters and expressions
            with db_manager.session_context() as session:
                # pylint: disable=protected-access  # Testing protected method
                SampleItem._query(
                    session,
                    (SampleItem.db_mapping.id == 1,),  # SQLAlchemy expression
                    {"name": "apple"},  # Filter kwargs
                )
                # pylint: enable=protected-access

        self.assertIn("must use filters or SQLAlchemy expressions but not both", str(context.exception))

    def test_all_with_no_results(self):
        """Test all() returns empty list when no matches"""
        items = SampleItem.all(category="nonexistent")
        self.assertEqual(len(items), 0)
        self.assertEqual(items, [])

    def test_all_ids_with_no_results(self):
        """Test all_ids() returns empty list when no matches"""
        ids = SampleItem.all_ids(category="nonexistent")
        self.assertEqual(len(ids), 0)
        self.assertEqual(ids, [])


# Test models for association testing (memo_set bug)
# Define ParentItem first, then ChildItem, then add has_many to ParentItem
class ParentItem(PersistableModel):
    """Parent model for testing has_many/belongs_to associations"""

    @classmethod
    def _schema(cls):
        cls._persist_as("parent_items")
        cls._id("id", Integer)
        cls._field("name", String(50))


class ChildItem(PersistableModel):
    """Child model for testing has_many/belongs_to associations"""

    @classmethod
    def _schema(cls):
        cls._persist_as("child_items")
        cls._id("id", Integer)
        cls._field("parent_id", Integer, refers_to="parent.id")  # pylint: disable=unexpected-keyword-arg
        cls._belongs_to("parent", ParentItem)
        cls._field("name", String(50))


# Add has_many after ChildItem is defined
ParentItem._has_many("children", ChildItem, foreign_keys=["parent_id"])  # pylint: disable=protected-access


class TestPersistableModelWithAssociations(unittest.TestCase):
    """Test cases for PersistableModel with associations (memo_set bug regression test)

    This test class verifies that the memo_set bug in _init_from_mapping is fixed.

    THE BUG:
    --------
    In persistable_model.py, the _init_from_mapping() method had a bug where it created
    memo_set from the memo parameter on line 292, but then used the original memo parameter
    on lines 308 and 317 instead of using memo_set.

    This caused TypeError when memo=None (the default) because:
    - Line 308: `if id(associated_data[0]) in memo` fails with "argument of type 'NoneType' is not iterable"
    - Line 317: `value = model(item, memo=memo)` passes None instead of the initialized set

    THE FIX:
    --------
    Lines 308 and 317 now use memo_set instead of memo.

    This test ensures the bug doesn't regress by actually creating models with associations
    and fetching them from the database.
    """

    @classmethod
    def setUpClass(cls):
        """Set up database schema once for all tests"""
        # pylint: disable=protected-access
        # Use same db_manager as other tests (already initialized in TestPersistableModelQueries)
        if not db_manager._engine:
            db_manager._engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
            db_manager._registry = registry()
            db_manager._service = "test"
        # pylint: enable=protected-access

        # Process schema for association models
        ChildItem.process_schema()
        ParentItem.process_schema()

    def setUp(self):
        """Set up test database and populate with test data"""
        # Create tables
        ParentItem.db_table.create(db_manager.engine, checkfirst=True)
        ChildItem.db_table.create(db_manager.engine, checkfirst=True)

    def tearDown(self):
        """Clean up test database"""
        ChildItem.db_table.drop(db_manager.engine, checkfirst=True)
        ParentItem.db_table.drop(db_manager.engine, checkfirst=True)

    def test_fetch_model_with_associations(self):
        """Test fetching model with belongs_to association (memo_set bug regression test)

        This test would have failed with the memo_set bug because:
        1. We insert a parent and child into the database with belongs_to association
        2. We fetch the child back using get()
        3. The fetch triggers _init_from_mapping with memo=None
        4. The method tries to load parent association
        5. Without the fix, line 308 would fail with: "argument of type 'NoneType' is not iterable"

        With the fix, memo_set is used instead of memo, so the test passes.
        """
        # Insert parent and child directly into database
        with db_manager.session_context() as session:
            # Create parent
            parent_mapping = ParentItem.db_mapping(id=1, name="Parent1")
            session.add(parent_mapping)

            # Create child that belongs_to the parent
            child_mapping = ChildItem.db_mapping(id=1, parent_id=1, name="Child1")
            session.add(child_mapping)

            session.commit()

        # Fetch child - this triggers _init_from_mapping with memo=None
        # The child has a belongs_to("parent") association, so _init_from_mapping
        # will try to load the associated parent record.
        #
        # Before the fix, this would raise at line 308:
        # TypeError: argument of type 'NoneType' is not iterable
        # when checking: if id(associated_data[0]) in memo
        #
        # After the fix (using memo_set instead of memo), this works correctly
        child = ChildItem.get(1)

        # Verify the child was fetched successfully
        self.assertIsNotNone(child)
        # pylint: disable=no-member  # Dynamic ORM attributes
        self.assertEqual(child.id, 1)  # type: ignore[attr-defined]
        self.assertEqual(child.name, "Child1")  # type: ignore[attr-defined]
        self.assertEqual(child.parent_id, 1)  # type: ignore[attr-defined]

        # Verify parent association was loaded (belongs_to with preload=True by default)
        parent = child.parent  # type: ignore[attr-defined]
        # pylint: enable=no-member
        self.assertIsNotNone(parent)
        # pylint: disable=no-member  # Dynamic ORM attributes
        self.assertEqual(parent.id, 1)  # type: ignore[attr-defined]
        self.assertEqual(parent.name, "Parent1")  # type: ignore[attr-defined]
        # pylint: enable=no-member


if __name__ == "__main__":
    unittest.main()
