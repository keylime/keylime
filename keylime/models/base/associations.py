from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keylime.models.base.model import Model


class ModelAssociation:
    def __init__(self, name, other_model, inverse_of=None):
        self._name = name
        self._private_member = "_" + name
        self._other_model = other_model
        self._inverse_of = inverse_of

    def __get__(self, record, objtype=None):
        if record is None:
            return self

        return self.get_record_set(record)

    def __delete__(self, record):
        self.get_record_set(record).clear()

    def get_record_set(self, record):
        if not hasattr(record, self._private_member):
            setattr(record, self._private_member, AssociatedRecordSet(record, self))

        return getattr(record, self._private_member)

    @property
    def name(self):
        return self._name

    @property
    def other_model(self):
        return self._other_model

    @property
    def inverse_of(self):
        return self._inverse_of


class GenericToOneAssociation(ModelAssociation):
    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        record_set = self.get_record_set(obj)

        if len(record_set) == 1:
            (record,) = record_set
            return record
        else:
            return None

    def __set__(self, record, other_record):
        if not isinstance(other_record, self.other_model):
            raise AssociationTypeMismatch(
                f"association '{self.name}' was given a value of type '{other_record.__class__.__name__}' which cannot "
                f"be converted to '{self.other_model.__name__}' as required by the '{record.__class__.__name__}' model"
            )

        record_set = self.get_record_set(record)
        record_set.clear()
        record_set.add(other_record)


class GenericToManyAssociation(ModelAssociation):
    pass


class DatabasePersistenceMixin:
    if TYPE_CHECKING:

        @property
        def name(self) -> str:
            ...

        @property
        def other_model(self) -> "Model":
            ...

    def __init__(self, name, other_model, foreign_key=None, preload=True, *args, **kwargs):
        self._foreign_key = foreign_key
        self._preload = preload

        args = [name, other_model, *args]

        super().__init__(*args, **kwargs)

    @property
    def foreign_key(self):
        # If the foreign_key for the association's model is not set, attempt to infer it from the associated model's
        # primary key. This is done on getting the foreign_key and not when the association is created because, at
        # time of instantiation, the associated model may not have been properly initialised yet
        if not self._foreign_key:
            if len(self.other_model.primary_key) != 1:
                raise AssociationDefinitionInvalid(
                    f"the foreign_key for database-backed association '{self.name}' was not given and cannot be "
                    f"inferred from the associated model '{self.other_model}'"
                )

            (foreign_key,) = self.other_model.primary_key
            self._foreign_key = foreign_key

            # TODO: This implementation should be moved into HasOneAssociation and HasManyAssociation with a
            # different implementation added for BelongsToAssociation

        return self._foreign_key

    @property
    def foreign_key_type(self):
        foreign_key_info = self.other_model.fields.get(self.foreign_key)

        if not foreign_key_info:
            raise AssociationDefinitionInvalid(
                f"the foreign_key '{self.foreign_key}' for database-backed association '{self.name}' does not "
                f"correspond to an field defined by the associated model '{self.other_model}'"
            )

        self._foreign_key_type = foreign_key_info.type

    @property
    def preload(self):
        return self._preload


class BelongsToAssociation(DatabasePersistenceMixin, GenericToOneAssociation):
    def __init__(self, *args, **kwargs):
        self._nullable = kwargs.get("nullable", False)
        super().__init__(*args, **kwargs)

    def __set__(self, record, other_record):
        (other_model_id_field,) = other_record.__class__.primary_key
        other_record_id = getattr(other_record, other_model_id_field)

        # If the associated record is identifiable by an field with a name as specified by self.foreign_key,
        # modify the parent record (which contains the association) to contain the id of the associated record
        if other_record_id:
            # # Add the id field to the parent record if it does not already exist
            # if not hasattr(record, f"{self.name}_id"):
            #     record.__class__._new_field(f"{self.name}_id", self.foreign_key_type, nullable=self.nullable)

            # # Set the id field in the parent record to point to the associated record
            # setattr(record, f"{self.name}_id", other_record_id)

            if hasattr(record, self.foreign_key):
                setattr(record, self.foreign_key, other_record_id)

        super().__set__(record, other_record)

    @property
    def nullable(self):
        return self._nullable


class HasOneAssociation(DatabasePersistenceMixin, GenericToOneAssociation):
    pass


class HasManyAssociation(DatabasePersistenceMixin, GenericToManyAssociation):
    pass


# TODO: Replace HasOneAssociation and HasManyAssociation with a single ReferencedByAssociation
# and rename BelongsToAssociation as ReferencesAssociation


class AssociatedRecordSet(set):
    def __init__(self, parent_record, association, *args, **kwargs):
        self._parent_record = parent_record
        self._association = association
        self._loaded = False
        super().__init__(*args, **kwargs)

    def add(self, record, populate_inverse=True):
        if not isinstance(record, self.model):
            raise AssociationTypeMismatch(
                f"value of type '{record.__class__.__name__}' cannot be added to AssociatedRecordSet of type"
                f"'{self.model.__name__}'"
            )

        # If the caller has indicated that the inverse association should be populated and the association does have
        # an inverse association defined, back-populate the inverse association by creating a reference to the
        # association's parent record in the record being added to the set
        if populate_inverse and self.association.inverse_of:
            # Get the record set of the inverse association
            inverse_association = getattr(record.__class__, self.association.inverse_of)
            inverse_record_set = inverse_association.get_record_set(record)

            # If the association is a "to-one" association, then its record set should always contain, at most, one
            # record, so clear the set before adding the parent record
            if isinstance(self.association, GenericToOneAssociation):
                inverse_record_set.clear()

            # Add the association's parent record to the record set of the inverse association
            inverse_record_set.add(self.parent_record, populate_inverse=False)

        super().add(record)

    @property
    def parent_record(self):
        return self._parent_record

    @property
    def association(self):
        return self._association

    @property
    def model(self):
        return self.association.other_model

    @property
    def loaded(self):
        return self.loaded


class ModelAssociationError(Exception):
    pass


class AssociationDefinitionInvalid(ModelAssociationError):
    pass


class AssociationValueInvalid(ModelAssociationError):
    pass


class AssociationNonNullable(AssociationValueInvalid):
    pass


class AssociationTypeMismatch(AssociationValueInvalid):
    pass
