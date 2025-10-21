"""
Unit tests for keylime.models.base.record_set and associated_record_set modules
"""

import unittest
from unittest.mock import MagicMock

from keylime.models.base.associated_record_set import AssociatedRecordSet
from keylime.models.base.basic_model import BasicModel
from keylime.models.base.record_set import RecordSet


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


if __name__ == "__main__":
    unittest.main()
