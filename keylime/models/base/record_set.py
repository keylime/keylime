from typing import Sequence, Union

import keylime.models.base.basic_model
import keylime.models.base.basic_model_meta


class RecordSet(set["BasicModel"]):

    def __init__(self, records: Sequence["BasicModel"], model: "BasicModelMeta" = None) -> None:
        if not records and not model:
            raise ValueError(f"{self.__class__.__name__} must be initialised with a sequence of records or a model")

        if model and not isinstance(model, keylime.models.base.basic_model_meta.BasicModelMeta):
            raise TypeError(f"model used to initialise {self.__class__.__name__} must be a 'BasicModelMeta' instance")

        self._model = model or type(records[0])

        for record in records:
            if not isinstance(record, keylime.models.base.basic_model.BasicModel):
                raise TypeError(f"records used to initialise {self.__class__.__name__} must be a 'BasicModel' instance")

            if not isinstance(record, self._model):
                raise TypeError(f"this RecordSet may only contain records of type '{self._model.__name__}'")

        super().__init__(records)
        self._order = list(records)

    def __repr__(self):
        if self._order:
            return f"{self.__class__.__name__}({self._order})"
        else:
            return f"{self.__class__.__name__}(model={self.model.__name__})"

    def __iter__(self):
        return iter(self._order)

    def __getitem__(self, arg):
        return self._order[arg]

    def __copy__(self):
        return self.copy()

    def add(self, record: "BasicModel") -> "RecordSet":
        if not isinstance(record, self.model):
            raise TypeError(
                f"value of type '{record.__class__.__name__}' cannot be added to {self.__class__.__name__} with "
                f"declared type of '{self.model.__name__}'"
            )

        if record not in self._order:
            self._order.append(record)

        super().add(record)
        return self

    def update(self, *others):
        for other in others:
            for record in other:
                self.add(record)

        return self

    def remove(self, record: "BasicModel") -> "RecordSet":
        if record not in self._order or record not in self:
            raise KeyError("cannot remove record which does not exist in record set")

        self._order.remove(record)
        super().remove(record)
        return self

    def discard(self, record: "BasicModel") -> "RecordSet":
        if record in self._order:
            self._order.remove(record)
            
        super().discard(record)
        return self

    def pop(self) -> "RecordSet":
        if not self._order or not self:
            raise KeyError("cannot pop from empty record set")

        record = self._order.pop()
        self.remove(record)
        return record

    def clear(self) -> "RecordSet":
        self._order.clear()
        super().clear()
        return self

    def to_list(self):
        return self._order.copy()
    
    def copy(self):
        record_set = super().copy()
        record_set._model = self._model
        record_set._order = self._order.copy()
        return record_set

    def copy(self):
        return RecordSet(self._order, model=self._model)

    def view(self):
        return RecordSetView(self)

    @property
    def model(self) -> "BasicModelMeta":
        return self._model


class RecordSetView:
    def __init__(self, parent):
        if not isinstance(parent, (RecordSet, RecordSetView)):
            raise TypeError("a new record set view can only be instantiated from a record set or other view")
             
        self._parent = parent
        self._content = parent.to_list()
        self._fallback = []

    def add(self, record):
        if record not in self.record_set:
            raise KeyError("cannot add record to view which is not present in the view's record set")

        if record in self._content:
            return self

        for i in reversed(range(self.record_set.to_list().index(record))):
            leader = self.record_set[i]

            if leader in self._content:
                break

        new_view = self.view()
        insert_before = new_view._content.index(leader) + 1
        new_view._content.insert(insert_before, record)
        return new_view

    def update(self, *others):
        new_view = self.view()

        for other in others:
            for record in other:
                new_view = new_view.add(record)

        if new_view._content == self._content:
            return self

        new_view._parent = self._parent
        return new_view

    def remove(self, record):
        if record not in self.record_set:
            raise KeyError("cannot remove record from view which is not present in the view's record set")

        if record not in self._content:
            raise KeyError("cannot remove record from view which is not present in the view")

        new_view = self.view()
        new_view._content.remove(record)
        return new_view

    def discard(self, record):
        if record not in self._content:
            return self

        new_view = self.remove(record)
        return new_view

    def pop(self):
        raise NotImplemented("cannot pop from record set view")

    def clear(self):
        if not self._content:
            return self

        new_view = self.view()
        new_view._content.clear()
        return new_view

    def _filter_func(self, func, criteria):
        if func:
            return func

        def default_filter_func(record):
            matches = True

            for field, value in criteria.items():
                if record.values.get(field) != value:
                    matches = False

            return matches

        return default_filter_func

    def filter(self, func=None, **criteria) -> "RecordSet":
        if not self._content:
            return self
            
        new_view = self.view()
        new_view._content = []

        for record in filter(self._filter_func(func, criteria), self._content):
            new_view._content.append(record)

        if new_view._content == self._content:
            return self

        return new_view

    def revert_if_empty(self):
        if self._content:
            return self

        if isinstance(self.parent, RecordSet):
            return RecordSetView(self.parent)
        else:
            return self.parent

    def result_if_empty(self, result):
        if not self._fallback:
            self._fallback = result

        return self
    
    def result(self):
        if self._content:
            return RecordSet(self._content)
        else:
            return self._fallback

    def to_list(self):
        return self._content.copy()

    def view(self):
        return RecordSetView(self)

    @property
    def parent(self) -> Union["RecordSet", "RecordSetView"]:
        return self._parent

    @property
    def record_set(self) -> "RecordSet":
        while True:
            parent = self.parent

            if isinstance(parent, RecordSet):
                return parent
