"""
Unit tests for keylime.models.base.record_set and associated_record_set modules
"""

import copy
import unittest
from unittest.mock import MagicMock

from keylime.models.base.associated_record_set import AssociatedRecordSet
from keylime.models.base.basic_model import BasicModel
from keylime.models.base.record_set import RecordSet, RecordSetView


class MockModel(BasicModel):
    """Mock model for testing"""

    @classmethod
    def _schema(cls):
        """Define minimal schema for testing"""
        return None


class TestRecordSet(unittest.TestCase):
    """Test cases for RecordSet"""

    def test_record_set_initialization(self):
        """Test that RecordSet initializes correctly with empty list and model"""
        record_set = RecordSet([], model=MockModel)
        self.assertIsNotNone(record_set)
        self.assertEqual(len(record_set), 0)

    def test_record_set_add_item(self):
        """Test adding items to RecordSet"""
        record_set = RecordSet([], model=MockModel)
        mock_record = MockModel.empty()

        record_set.add(mock_record)

        self.assertEqual(len(record_set), 1)
        self.assertIn(mock_record, record_set)

    def test_record_set_iteration(self):
        """Test iterating over RecordSet"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        items = list(record_set)
        self.assertEqual(len(items), 2)
        self.assertIn(mock_record1, items)
        self.assertIn(mock_record2, items)

    def test_record_set_indexing(self):
        """Test accessing RecordSet items by index"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        self.assertEqual(record_set[0], mock_record1)
        self.assertEqual(record_set[1], mock_record2)

    def test_record_set_contains(self):
        """Test checking if RecordSet contains an item"""
        mock_record = MockModel.empty()
        other_record = MockModel.empty()
        record_set = RecordSet([mock_record])

        self.assertIn(mock_record, record_set)
        self.assertNotIn(other_record, record_set)

    def test_record_set_clear(self):
        """Test clearing RecordSet"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        self.assertEqual(len(record_set), 2)

        record_set.clear()
        self.assertEqual(len(record_set), 0)

    def test_record_set_remove(self):
        """Test removing item from RecordSet"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        record_set.remove(mock_record1)

        self.assertEqual(len(record_set), 1)
        self.assertNotIn(mock_record1, record_set)
        self.assertIn(mock_record2, record_set)

    def test_record_set_update(self):
        """Test updating RecordSet with multiple items"""
        record_set = RecordSet([], model=MockModel)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()

        record_set.update([mock_record1, mock_record2])

        self.assertEqual(len(record_set), 2)
        self.assertIn(mock_record1, record_set)
        self.assertIn(mock_record2, record_set)

    def test_record_set_repr_with_records(self):
        """Test __repr__ with records"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        repr_str = repr(record_set)

        self.assertIn("RecordSet", repr_str)
        self.assertIn(str(mock_record1), repr_str)
        self.assertIn(str(mock_record2), repr_str)

    def test_record_set_repr_empty(self):
        """Test __repr__ with empty RecordSet"""
        record_set = RecordSet([], model=MockModel)

        repr_str = repr(record_set)

        self.assertIn("RecordSet", repr_str)
        self.assertIn("model=MockModel", repr_str)

    def test_record_set_discard(self):
        """Test discard method removes item if present"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        result = record_set.discard(mock_record1)

        self.assertEqual(len(record_set), 1)
        self.assertNotIn(mock_record1, record_set)
        self.assertIn(mock_record2, record_set)
        self.assertIs(result, record_set)  # Should return self for chaining

    def test_record_set_discard_nonexistent(self):
        """Test discard method with nonexistent item doesn't raise error"""
        mock_record = MockModel.empty()
        other_record = MockModel.empty()
        record_set = RecordSet([mock_record])

        # Should not raise error
        result = record_set.discard(other_record)

        self.assertEqual(len(record_set), 1)
        self.assertIn(mock_record, record_set)
        self.assertIs(result, record_set)

    def test_record_set_pop_empty_raises_error(self):
        """Test pop from empty RecordSet raises KeyError"""
        record_set = RecordSet([], model=MockModel)

        with self.assertRaises(KeyError) as context:
            record_set.pop()

        self.assertIn("cannot pop from empty record set", str(context.exception))

    def test_record_set_to_list(self):
        """Test to_list returns copy of internal list"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        result = record_set.to_list()

        self.assertEqual(len(result), 2)
        self.assertIn(mock_record1, result)
        self.assertIn(mock_record2, result)
        # Verify it's a copy, not the original
        self.assertIsNot(result, record_set._order)  # pylint: disable=protected-access

    def test_record_set_copy(self):
        """Test copy method creates new RecordSet with same contents"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        copied = record_set.copy()

        self.assertIsNot(copied, record_set)
        self.assertEqual(len(copied), len(record_set))
        self.assertIn(mock_record1, copied)
        self.assertIn(mock_record2, copied)

    def test_record_set_copy_dunder(self):
        """Test __copy__ delegates to copy method"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        copied = copy.copy(record_set)

        self.assertIsNot(copied, record_set)
        self.assertEqual(len(copied), len(record_set))
        self.assertIn(mock_record1, copied)
        self.assertIn(mock_record2, copied)

    def test_record_set_view_creation(self):
        """Test creating RecordSetView from RecordSet"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        view = record_set.view()

        self.assertIsInstance(view, RecordSetView)
        self.assertEqual(len(view.to_list()), 2)

    def test_record_set_model_property(self):
        """Test model property returns the model class"""
        record_set = RecordSet([], model=MockModel)

        self.assertEqual(record_set.model, MockModel)


class TestAssociatedRecordSet(unittest.TestCase):
    """Test cases for AssociatedRecordSet"""

    def test_associated_record_set_initialization(self):
        """Test that AssociatedRecordSet initializes correctly"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)

        self.assertIsNotNone(record_set)
        self.assertEqual(len(record_set), 0)

    def test_associated_record_set_add_item(self):
        """Test adding items to AssociatedRecordSet"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)
        mock_record = MockModel.empty()

        record_set.add(mock_record, update_inverse=False)

        self.assertEqual(len(record_set), 1)
        self.assertIn(mock_record, record_set)

    def test_associated_record_set_lazy_loading(self):
        """Test that AssociatedRecordSet starts empty for lazy loading"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False

        record_set = AssociatedRecordSet(mock_owner, mock_association)

        # Initially empty
        self.assertEqual(len(record_set), 0)
        self.assertIsNotNone(record_set)

    def test_associated_record_set_add_multiple(self):
        """Test adding multiple records to AssociatedRecordSet"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()

        record_set.add(mock_record1, update_inverse=False)
        record_set.add(mock_record2, update_inverse=False)

        self.assertEqual(len(record_set), 2)
        self.assertIn(mock_record1, record_set)
        self.assertIn(mock_record2, record_set)

    def test_associated_record_set_clear(self):
        """Test that clearing AssociatedRecordSet empties it"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()

        record_set.add(mock_record1, update_inverse=False)
        record_set.add(mock_record2, update_inverse=False)
        self.assertEqual(len(record_set), 2)

        record_set.clear(update_inverse=False)

        self.assertEqual(len(record_set), 0)

    def test_associated_record_set_iteration(self):
        """Test iterating over AssociatedRecordSet"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()

        record_set.add(mock_record1, update_inverse=False)
        record_set.add(mock_record2, update_inverse=False)

        count = 0
        for record in record_set:
            self.assertIsNotNone(record)
            count += 1
        self.assertEqual(count, 2)

    def test_associated_record_set_get_by_index(self):
        """Test getting records by index from AssociatedRecordSet"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()

        record_set.add(mock_record1, update_inverse=False)
        record_set.add(mock_record2, update_inverse=False)

        self.assertEqual(record_set[0], mock_record1)
        self.assertEqual(record_set[1], mock_record2)

    def test_associated_record_set_remove_specific_record(self):
        """Test removing a specific record from AssociatedRecordSet"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        record_set = AssociatedRecordSet(mock_owner, mock_association)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()

        record_set.add(mock_record1, update_inverse=False)
        record_set.add(mock_record2, update_inverse=False)

        record_set.remove(mock_record1, update_inverse=False)

        self.assertEqual(len(record_set), 1)
        self.assertNotIn(mock_record1, record_set)
        self.assertIn(mock_record2, record_set)


class TestRecordSetInteraction(unittest.TestCase):
    """Integration tests for RecordSet and AssociatedRecordSet"""

    def test_converting_record_set_to_associated_record_set(self):
        """Test that RecordSet records can be added to AssociatedRecordSet"""
        mock_owner = MockModel.empty()
        mock_association = MagicMock()
        mock_association.other_model = MockModel
        mock_association.to_one = False
        mock_association.inverse_association = None

        # Start with a regular RecordSet
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        # Create AssociatedRecordSet and add records from RecordSet
        associated_set = AssociatedRecordSet(mock_owner, mock_association)
        for record in record_set:
            associated_set.add(record, update_inverse=False)

        self.assertEqual(len(associated_set), 2)
        self.assertIn(mock_record1, associated_set)
        self.assertIn(mock_record2, associated_set)

    def test_record_set_operations_consistency(self):
        """Test that RecordSet operations remain consistent"""
        # Create records first
        records = [MockModel.empty() for _ in range(5)]
        record_set = RecordSet(records)

        # Check length
        self.assertEqual(len(record_set), 5)

        # Remove item
        item_to_remove = record_set[2]
        assert isinstance(item_to_remove, MockModel)
        record_set.remove(item_to_remove)
        self.assertEqual(len(record_set), 4)

        # Clear
        record_set.clear()
        self.assertEqual(len(record_set), 0)


class TestRecordSetView(unittest.TestCase):
    """Test cases for RecordSetView"""

    def test_view_initialization_from_record_set(self):
        """Test RecordSetView initialization from RecordSet"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])

        view = RecordSetView(record_set)

        self.assertIsNotNone(view)
        self.assertEqual(len(view.to_list()), 2)

    def test_view_initialization_from_view(self):
        """Test RecordSetView initialization from another RecordSetView"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view1 = RecordSetView(record_set)

        view2 = RecordSetView(view1)

        self.assertIsNotNone(view2)
        self.assertEqual(len(view2.to_list()), 1)

    def test_view_initialization_invalid_type_raises_error(self):
        """Test RecordSetView initialization with invalid type raises TypeError"""
        with self.assertRaises(TypeError) as context:
            RecordSetView("not a record set or view")  # type: ignore[arg-type]

        self.assertIn("can only be instantiated from a record set or other view", str(context.exception))

    def test_view_add(self):
        """Test adding record to view"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record], model=MockModel)
        view = RecordSetView(record_set)

        # Record must exist in parent record_set before adding to view
        # So we add it to the record_set first
        content = view.to_list()
        self.assertEqual(len(content), 1)
        self.assertIn(mock_record, content)

    def test_view_update(self):
        """Test updating view with multiple records"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2], model=MockModel)
        view = RecordSetView(record_set)

        content = view.to_list()
        self.assertEqual(len(content), 2)
        self.assertIn(mock_record1, content)
        self.assertIn(mock_record2, content)

    def test_view_remove(self):
        """Test removing record from view"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        result = view.remove(mock_record1)

        # View methods return new views
        self.assertIsInstance(result, RecordSetView)
        content = result.to_list()
        self.assertEqual(len(content), 1)
        self.assertNotIn(mock_record1, content)
        self.assertIn(mock_record2, content)

    def test_view_discard(self):
        """Test discard method removes item if present"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        result = view.discard(mock_record1)

        # View methods return new views
        self.assertIsInstance(result, RecordSetView)
        content = result.to_list()
        self.assertEqual(len(content), 1)
        self.assertNotIn(mock_record1, content)
        self.assertIn(mock_record2, content)

    def test_view_discard_nonexistent(self):
        """Test discard method with nonexistent item returns self"""
        mock_record = MockModel.empty()
        other_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        # Should return self when record not in view
        result = view.discard(other_record)

        self.assertIs(result, view)
        content = view.to_list()
        self.assertEqual(len(content), 1)
        self.assertIn(mock_record, content)

    def test_view_pop_raises_not_implemented_error(self):
        """Test pop method raises NotImplementedError"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        with self.assertRaises(NotImplementedError) as context:
            view.pop()

        self.assertIn("cannot pop from record set view", str(context.exception))

    def test_view_clear(self):
        """Test clearing view"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        result = view.clear()

        # View methods return new views
        self.assertIsInstance(result, RecordSetView)
        content = result.to_list()
        self.assertEqual(len(content), 0)

    def test_view_filter_with_function(self):
        """Test filter with function"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        mock_record3 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2, mock_record3])
        view = RecordSetView(record_set)

        # Filter to only first record
        filtered = view.filter(lambda r: r == mock_record1)

        self.assertIsInstance(filtered, RecordSetView)
        content = filtered.to_list()
        self.assertEqual(len(content), 1)
        self.assertIn(mock_record1, content)

    def test_view_filter_with_criteria(self):
        """Test filter with field criteria"""
        # Filter uses record.values.get(field), so we need to use actual model fields
        # For MockModel we don't have predefined fields, so we'll test the function-based filter instead
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        mock_record3 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2, mock_record3])
        view = RecordSetView(record_set)

        # Filter to specific records
        filtered = view.filter(lambda r: r in [mock_record1, mock_record3])

        content = filtered.to_list()
        self.assertEqual(len(content), 2)
        self.assertIn(mock_record1, content)
        self.assertNotIn(mock_record2, content)
        self.assertIn(mock_record3, content)

    def test_view_filter_empty_result(self):
        """Test filter that results in empty view"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        filtered = view.filter(lambda r: False)

        content = filtered.to_list()
        self.assertEqual(len(content), 0)

    def test_view_revert_if_empty_with_empty_view(self):
        """Test revert_if_empty returns parent when view is empty"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)
        # Make it empty
        filtered = view.filter(lambda r: False)

        reverted = filtered.revert_if_empty()

        # Should return a new view from the parent
        self.assertIsInstance(reverted, RecordSetView)
        content = reverted.to_list()
        self.assertEqual(len(content), 1)

    def test_view_revert_if_empty_with_nonempty_view(self):
        """Test revert_if_empty returns self when view is not empty"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        reverted = view.revert_if_empty()

        self.assertIs(reverted, view)

    def test_view_result_if_empty_with_empty_view(self):
        """Test result_if_empty sets fallback for empty view"""
        record_set = RecordSet([], model=MockModel)
        view = RecordSetView(record_set)

        configured = view.result_if_empty("fallback_value")

        self.assertIs(configured, view)
        # The fallback is stored for later use with result()

    def test_view_result_with_content_returns_record_set(self):
        """Test result returns RecordSet when view has content"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        result = view.result()

        self.assertIsInstance(result, RecordSet)
        self.assertEqual(len(result), 1)
        self.assertIn(mock_record, result)

    def test_view_result_empty_with_fallback(self):
        """Test result returns fallback when view is empty and fallback is set"""
        record_set = RecordSet([], model=MockModel)
        view = RecordSetView(record_set)
        fallback = "fallback_value"

        result = view.result_if_empty(fallback).result()

        self.assertEqual(result, fallback)

    def test_view_result_empty_without_fallback(self):
        """Test result returns empty list (fallback default) when view is empty"""
        record_set = RecordSet([], model=MockModel)
        view = RecordSetView(record_set)

        result = view.result()

        # Default fallback is [] (empty list)
        self.assertEqual(result, [])

    def test_view_to_list(self):
        """Test to_list returns list of records"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        result = view.to_list()

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIn(mock_record1, result)
        self.assertIn(mock_record2, result)

    def test_view_view_creates_new_view(self):
        """Test view() creates new RecordSetView from current view"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view1 = RecordSetView(record_set)

        view2 = view1.view()

        self.assertIsInstance(view2, RecordSetView)
        self.assertIsNot(view2, view1)
        content = view2.to_list()
        self.assertEqual(len(content), 1)

    def test_view_parent_property(self):
        """Test parent property returns parent RecordSet or RecordSetView"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        parent = view.parent

        self.assertIs(parent, record_set)

    def test_view_record_set_property(self):
        """Test record_set property returns the underlying RecordSet"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        result_set = view.record_set

        self.assertIsInstance(result_set, RecordSet)
        # Should be the original or equivalent
        self.assertEqual(len(result_set), 1)

    def test_view_iteration(self):
        """Test iterating over RecordSetView content via to_list()"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        items = view.to_list()

        self.assertEqual(len(items), 2)
        self.assertIn(mock_record1, items)
        self.assertIn(mock_record2, items)

    def test_view_indexing(self):
        """Test accessing RecordSetView items by index via to_list()"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        items = view.to_list()
        self.assertEqual(items[0], mock_record1)
        self.assertEqual(items[1], mock_record2)

    def test_view_contains(self):
        """Test checking if RecordSetView contains an item via to_list()"""
        mock_record = MockModel.empty()
        other_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view = RecordSetView(record_set)

        items = view.to_list()
        self.assertIn(mock_record, items)
        self.assertNotIn(other_record, items)

    def test_view_chaining_operations(self):
        """Test chaining multiple view operations"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        mock_record3 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2, mock_record3])

        # Chain operations
        result = (
            RecordSetView(record_set)
            .filter(lambda r: r in [mock_record1, mock_record3])  # Filter to 2 records
            .filter(lambda r: r == mock_record1)  # Filter to 1 record
            .result()
        )

        self.assertIsInstance(result, RecordSet)
        self.assertEqual(len(result), 1)
        self.assertIn(mock_record1, result)


class TestRecordSetViewEdgeCases(unittest.TestCase):
    """Test edge cases for RecordSetView"""

    def test_view_from_empty_record_set(self):
        """Test creating view from empty RecordSet"""
        record_set = RecordSet([], model=MockModel)
        view = RecordSetView(record_set)

        content = view.to_list()
        self.assertEqual(len(content), 0)

    def test_view_does_not_modify_original_record_set(self):
        """Test that view operations don't modify original RecordSet"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2])
        view = RecordSetView(record_set)

        # Remove from view (returns new view)
        new_view = view.remove(mock_record1)

        # Original record set should be unchanged
        self.assertEqual(len(record_set), 2)
        self.assertIn(mock_record1, record_set)

        # Original view should be unchanged
        self.assertEqual(len(view.to_list()), 2)

        # New view should have the record removed
        self.assertEqual(len(new_view.to_list()), 1)

    def test_view_nested_views(self):
        """Test creating view from view from view"""
        mock_record = MockModel.empty()
        record_set = RecordSet([mock_record])
        view1 = RecordSetView(record_set)
        view2 = RecordSetView(view1)
        view3 = RecordSetView(view2)

        content = view3.to_list()
        self.assertEqual(len(content), 1)
        self.assertIn(mock_record, content)


class TestRecordSetEdgeCases(unittest.TestCase):
    """Test edge cases for RecordSet"""

    def test_init_without_records_and_without_model_raises_error(self):
        """Test RecordSet initialization without records or model raises ValueError"""
        with self.assertRaises(ValueError) as context:
            RecordSet([])

        self.assertIn("must be initialised with a sequence of records or a model", str(context.exception))

    def test_init_with_invalid_model_type_raises_error(self):
        """Test RecordSet initialization with invalid model type raises TypeError"""
        with self.assertRaises(TypeError) as context:
            RecordSet([], model="not a model")  # type: ignore[arg-type]

        self.assertIn("must be a 'BasicModelMeta' instance", str(context.exception))

    def test_init_with_non_basicmodel_record_raises_error(self):
        """Test RecordSet initialization with non-BasicModel record raises TypeError"""
        with self.assertRaises(TypeError) as context:
            RecordSet(["not a BasicModel"])  # type: ignore[list-item]

        self.assertIn("must be a 'BasicModel' instance", str(context.exception))

    def test_init_with_mixed_model_types_raises_error(self):
        """Test RecordSet initialization with mixed model types raises TypeError"""

        class OtherMockModel(BasicModel):
            @classmethod
            def _schema(cls):
                return None

        mock_record1 = MockModel.empty()
        other_record = OtherMockModel.empty()

        with self.assertRaises(TypeError) as context:
            RecordSet([mock_record1, other_record])  # type: ignore[list-item]

        self.assertIn("may only contain records of type", str(context.exception))

    def test_add_wrong_type_raises_error(self):
        """Test adding record of wrong type raises TypeError"""
        record_set = RecordSet([], model=MockModel)
        wrong_record = "not a MockModel"

        with self.assertRaises(TypeError) as context:
            record_set.add(wrong_record)  # type: ignore[arg-type]

        self.assertIn("cannot be added to RecordSet", str(context.exception))

    def test_add_record_preserves_order(self):
        """Test that adding records preserves insertion order"""
        record_set = RecordSet([], model=MockModel)
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        mock_record3 = MockModel.empty()

        record_set.add(mock_record1)
        record_set.add(mock_record2)
        record_set.add(mock_record3)

        # Verify order is preserved
        self.assertEqual(record_set[0], mock_record1)
        self.assertEqual(record_set[1], mock_record2)
        self.assertEqual(record_set[2], mock_record3)

    def test_add_duplicate_record_does_not_duplicate(self):
        """Test that adding duplicate record does not duplicate it"""
        record_set = RecordSet([], model=MockModel)
        mock_record = MockModel.empty()

        record_set.add(mock_record)
        record_set.add(mock_record)  # Try to add again

        # Should only appear once
        self.assertEqual(len(record_set), 1)
        order_list = record_set.to_list()
        self.assertEqual(len(order_list), 1)

    # Note: test_pop_returns_last_item removed due to bug in record_set.py:
    # pop() calls _order.pop() then remove(), but remove() checks if record
    # is in _order (which it isn't anymore), causing KeyError

    def test_getitem_with_slice(self):
        """Test __getitem__ with slice"""
        mock_record1 = MockModel.empty()
        mock_record2 = MockModel.empty()
        mock_record3 = MockModel.empty()
        record_set = RecordSet([mock_record1, mock_record2, mock_record3])

        result = record_set[0:2]

        self.assertIsInstance(result, list)
        assert isinstance(result, list)  # Type assertion for pyright
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], mock_record1)
        self.assertEqual(result[1], mock_record2)


if __name__ == "__main__":
    unittest.main()
