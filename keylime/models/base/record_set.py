from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keylime.models.base.basic_model_meta import BasicModelMeta
    from keylime.models.base.basic_model import BasicModel


class RecordSet(set["BasicModel"]):

    def __init__(self, model: "BasicModelMeta") -> None:
        self._model = model
        self._mask = []
        self._previous_mask = []
        self._original_mask = []
        self._i = 0
        super().__init__()

    def __repr__(self):
        return f"{self.__class__.__name__}(mask={self._mask})"

    def __iter__(self):
        self._i = 0
        return self

    def __next__(self):
        if self._i >= len(self._mask):
            raise StopIteration

        record = self._mask[self._i]
        self._i += 1
        return record

    def __getitem__(self, arg):
        return self._original_mask[arg]

    def __copy__(self):
        record_set_copy = self.__class__(self.model)

        for record in self._original_mask:
            record_set_copy.add(record)

        record_set_copy._mask = self._mask.copy()
        record_set_copy._previous_mask = self._previous_mask.copy()

        return record_set_copy

    def copy(self):
        return self.__copy__()

    def all(self) -> "RecordSet":
        record_set_copy = self.copy()
        record_set_copy._mask = self._original_mask.copy()
        return record_set_copy

    def add(self, record: "BasicModel") -> "RecordSet":
        if not isinstance(record, self.model):
            raise TypeError(
                f"value of type '{record.__class__.__name__}' cannot be added to RecordSet with declared type of "
                f"'{self.model.__name__}'"
            )

        if record not in self:
            self._previous_mask = self._mask.copy()
            self._mask.append(record)
            self._original_mask.append(record)
            super().add(record)
            
        return self

    def update(self, *others):
        previous_mask = self._mask.copy()

        for other in others:
            for record in other:
                self.add(record)

        self._previous_mask = previous_mask

    def remove(self, record: "BasicModel") -> "RecordSet":
        if record in self._mask:
            self._previous_mask = self._mask.copy()
            self._mask.remove(record)
        
        self._original_mask.remove(record)
        super().remove(record)
        return self

    def discard(self, record: "BasicModel") -> "RecordSet":
        if record in self._mask:
            self._previous_mask = self._mask.copy()
            self._mask.remove(record)
        
        self._original_mask.remove(record)
        super().discard(record)
        return self

    def pop(self) -> "RecordSet":
        record = super().pop()

        if record in self._mask:
            self._previous_mask = self._mask.copy()
            self._mask.remove(record)

        self._original_mask.remove(record)
        return record

    def clear(self) -> "RecordSet":
        self._previous_mask = self._mask.copy()
        self._mask.clear()
        self._original_mask.clear()
        super().clear()
        return self

    def reset(self) -> "RecordSet":
        self._mask = self._original_mask.copy()
        return self

    def extend_mask(self, new_mask):
        for record in new_mask:
            if record not in self:
                raise ValueError("cannot update mask with foreign record not in RecordSet")

            self._mask.append(record)

        return self

    def filter(self, filter_func=None, **criteria) -> "RecordSet":
        if not self._mask:
            return self

        def default_filter_func(record):
            matches = True

            for field, value in criteria.items():
                if record.values.get(field) != value:
                    matches = False

            return matches

        if not filter_func:
            filter_func = default_filter_func
            
        new_mask = []

        for record in filter(filter_func, self._mask):
            new_mask.append(record)

        self._previous_mask = self._mask.copy()
        self._mask = new_mask

        return self

    def sort(self, sort_by=None, reverse=False) -> "RecordSet":
        if not self._mask:
            return self

        def default_sort_func(record):
            return record.values.get(sort_by)

        mask = self._mask.copy()
        
        if isinstance(sort_by, str):
            mask.sort(key=default_sort_func, reverse=reverse)
        else:
            mask.sort(key=sort_by, reverse=reverse)

        if mask != self._mask:
            self._previous_mask = self._mask.copy()
            self._mask = new_mask

        return self

    def reverse(self) -> "RecordSet":
        self._previous_mask = self._mask.copy()
        self._mask.reverse()
        return self

    def if_empty(self, func):
        if not self._mask:
            func()

        return self

    def if_newly_empty(self, func):
        if self._previous_mask and not self._mask:
            func()

        return self

    @property
    def model(self) -> "BasicModelMeta":
        return self._model

    @property
    def mask(self):
        return self._mask.copy()