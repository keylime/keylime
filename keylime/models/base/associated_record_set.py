from keylime.models.base.record_set import RecordSet, RecordSetView


class AssociatedRecordSet(RecordSet):
    """An AssociatedRecordSet contains a set of model instances (i.e., *records*) linked to a *parent record* by way of
    an association established between two models. With a "to-many" association, the set can contain an unbounded number
    of records but with a "to-one" association, the set will only ever contain one at most.
    """

    def __init__(self, parent_record: "BasicModel", association: "ModelAssociation") -> None:
        self._parent_record = parent_record
        self._association = association
        super().__init__([], model = association.other_model)

    def _add_to_inverse(self, *inverse_records):
        if not self.association.inverse_association:
            return

        for inverse_record in inverse_records:
            # Get the record set of the inverse association
            inverse_record_set = self.association.inverse_association.get_record_set(inverse_record)  # type: ignore

            # Add the association's parent record to the record set of the inverse association
            inverse_record_set.add(self.parent_record, update_inverse=False)

    def _remove_from_inverse(self, *inverse_records):
        if not self.association.inverse_association:
            return

        for inverse_record in inverse_records:
            # Get the record set of the inverse association
            inverse_record_set = self.association.inverse_association.get_record_set(inverse_record)  # type: ignore

            # Remove the association's parent record to the record set of the inverse association
            inverse_record_set.discard(self.parent_record, update_inverse=False)

    def add(self, record: "BasicModel", update_inverse: bool = True) -> "AssociatedRecordSet":
        # If the association is a "to-one" association, then its record set should always contain, at most, one
        # record, so clear the set before adding the record
        if self.association.to_one:
            self.clear()

        super().add(record)

        if update_inverse:
            self._add_to_inverse(record)

        return self

    def update(self, *others, update_inverse: bool = True) -> "AssociatedRecordSet":
        super().update(*others)

        if update_inverse:
            unique_additions = set()
            unique_additions.update(*others)
            self._add_to_inverse(*unique_additions)

        return self

    def remove(self, record: "BasicModel", update_inverse: bool = True) -> "AssociatedRecordSet":
        super().remove(record)

        if update_inverse:
            self._remove_from_inverse(record)

        return self

    def discard(self, record: "BasicModel", update_inverse: bool = True) -> "AssociatedRecordSet":
        super().discard(record)

        if update_inverse:
            self._remove_from_inverse(record)

        return self

    def pop(self, update_inverse: bool = True) -> "AssociatedRecordSet":
        record = super().pop()

        if update_inverse:
            self._remove_from_inverse(record)

        return record

    def clear(self, update_inverse: bool = True) -> "AssociatedRecordSet":
        records = self.to_list()

        super().clear()

        if update_inverse:
            self._remove_from_inverse(*records)

        return self

    def copy(self):
        """Copy the AssociatedRecordSet as a RecordSet so that the returned set is no longer linked to an associated
        record set. This means that modifications to the copied set are not reflected in the inverse record set of the
        original.
        """
        return super().copy()

    @property
    def parent_record(self) -> "BasicModel":
        return self._parent_record

    @property
    def association(self) -> "ModelAssociation":
        return self._association
