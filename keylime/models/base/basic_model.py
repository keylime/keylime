import base64
import binascii
import re
from abc import ABC, abstractmethod
from types import MappingProxyType

from sqlalchemy.dialects.sqlite import dialect as sqlite_dialect
from sqlalchemy.types import PickleType

from keylime.models.base.errors import FieldValueInvalid, UndefinedField
from keylime.models.base.field import ModelField


class BasicModel(ABC):
    """A model is a class which represents a data object in the system, each with a number of defined "fields".
    Individual instances are known as "records" and contain values for the model's fields. Models encapsulate the
    functionality related to querying, manipulating, validating and displaying records.

    The BasicModel abstract class provides the basic functionality common to all models including:

    * a domain-specific language (DSL) for specifying a schema to which individual records are expected to adhere;
    * an validation API for checking that the fields adhere to an expected format; and
    * an API for collecting changes to a record and applying them if they pass validation rules.

    If you need to persist a model to the database, you should subclass ``PersistableModel`` instead (which itself
    inherits from ``BasicModel``).
    """

    BUILT_IN_INST_ATTRS = [
        "record_values",
        "_record_values",
        "changes",
        "_changes",
        "values",
        "errors",
        "_errors",
        "changes_valid",
    ]

    _schema_processed = False

    @classmethod
    @abstractmethod
    def _schema(cls):
        pass

    @classmethod
    def _clear_model(cls):
        cls._fields = dict()
        cls._associations = dict()

    @classmethod
    def _process_schema(cls):
        # If schema has already been processed (and no changes have been made since), do not process again
        if cls._schema_processed:
            return

        # Prevent schema from being reprocessed unnecessarily
        cls._schema_processed = True

        # Set class variables afresh whenever the schema is processed to ensure that methods defined on the class always
        # access the model's own unique copy of the variables instead of variables further up the class hierarchy
        cls._clear_model()

        # Set up schema as defined by the implementing class
        cls._schema()

    @classmethod
    def _new_field(cls, name, type, nullable=False):
        # Create new model field
        field = ModelField(name, type, nullable)
        # Add model field to the model's list of fields
        cls._fields[name] = field
        # Make model field accessible as a member of the class and, thereby, any objects created therefrom
        setattr(cls, name, field)

        return field

    @classmethod
    def _field(cls, name, type, nullable=False):
        # TODO: Add validation
        cls._new_field(name, type, nullable)

    @classmethod
    def empty(cls):
        return cls()

    @classmethod
    @property
    def _repr_fields(cls):
        field_names = []
        count = 0

        for name in cls.fields.keys():
            if count >= 5:
                break

            field_names.append(name)
            count += 1

        return field_names

    @classmethod
    @property
    def persistable(cls):
        return False

    @classmethod
    @property
    def fields(cls):
        cls._process_schema()
        return MappingProxyType(cls._fields)

    @classmethod
    @property
    def associations(cls):
        cls._process_schema()
        return MappingProxyType(cls._associations)

    def __init__(self, data={}, process_associations=True):
        self.__class__._process_schema()

        self._record_values = dict()
        self._changes = dict()
        self._errors = dict()

        if isinstance(data, dict):
            return self._init_from_dict(data, process_associations)
        else:
            raise TypeError(
                f"model '{self.__class__.__name__}' cannot be initialised with data of type '{data.__class__.__name__}'"
            )

    def _init_from_dict(self, data, process_associations):
        for name, value in data:
            self.change(name, value)

        self._force_commit_changes()

    def __setattr__(self, name, value):
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
            public_name = name[1:]
        else:
            public_name = name

        if (
            name not in dir(self)
            and name not in self.__class__.BUILT_IN_INST_ATTRS
            and public_name not in self.__class__.fields.keys()
            and public_name not in self.__class__.associations.keys()
        ):
            raise AttributeError(
                f"the schema for model '{self.__class__.__name__}' does not define a field '{public_name}'"
            )

        super(BasicModel, self).__setattr__(name, value)

    def __getattribute__(self, name):
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
            public_name = name[1:]
        else:
            public_name = name

        try:
            return super(BasicModel, self).__getattribute__(name)
        except AttributeError:
            raise AttributeError(
                f"the schema for model '{self.__class__.__name__}' does not define a field '{public_name}'"
            )

    def __repr__(self):
        """Returns a code-like string representation of the model instance

        :returns: string
        """
        repr = f"{self.__class__.__name__}("
        repr_fields = self.__class__._repr_fields
        count = 0

        for field_name in repr_fields:
            field_value = str(getattr(self, field_name))
            field_value = (field_value[:32] + "...") if len(field_value) > 32 else field_value

            repr += f"{field_name}: {field_value}, "
            count += 1

        if count < len(repr_fields):
            repr += "..."
        else:
            repr = repr.rstrip(", ")

        repr += ")"

        return repr

    def render(self, only=None):
        data = {}

        for name, field in self.__class__.fields.items():
            if only and name not in only:
                continue

            value = getattr(self, name)

            if hasattr(field.type, "render_object") and callable(getattr(field.type, "render_object")):
                value = field.type.render_object(value)

            data[name] = value

        return data

    def clear_changes(self):
        self._changes.clear()
        self._errors.clear()

    def change(self, name, value):
        if name not in self.__class__.fields:
            raise UndefinedField(f"field '{name}' does not exist in model '{self.__class__.__name__}'")

        # Reset the errors for the field to an empty list
        self._errors[name] = list()

        # Get Field instance for name in order to obtain its type (TypeEngine object)
        field = self.__class__.fields[name]
        # Get processor which translates values of the given type to a format which can be stored in a DB
        bind_processor = field.type.bind_processor(sqlite_dialect())
        # Get processor which translates values retrieved by a DB query according to the field type
        result_processor = field.type.result_processor(sqlite_dialect(), None)

        try:
            # Process incoming value as if it were to be stored in a DB (if type requires inbound processing)
            value = bind_processor(value) if bind_processor else value
            # Process resulting value as if it were being retrieved from a DB (if type requires outbound processing)
            value = result_processor(value) if result_processor else value
            # Add value (processed according to the field type) to the model instance's collection of changes
            self._changes[name] = value
        except:
            # If the above mock DB storage and retrieval fails, the incoming value is of an incorrect type for the field
            if hasattr(field.type, "type_mismatch_msg") and not callable(getattr(field.type, "type_mismatch_msg")):
                # Some custom types provide a special "invalid type" message
                self._add_error(name, field.type.type_mismatch_msg)
            else:
                self._add_error(name, "is of an incorrect type")

    def cast_changes(self, changes, permitted={}):
        for name, value in changes.items():
            if (name not in permitted) or (name not in self.__class__.fields):
                continue

            self.change(name, value)

    def commit_changes(self):
        if not self.changes_valid:
            raise FieldValueInvalid(f"pending changes for model '{self.__class__.__name__}' have validation errors")

        for name, value in self._changes.items():
            self._record_values[name] = value

        self.clear_changes()

    def _force_commit_changes(self):
        for name, value in self._changes.items():
            self._record_values[name] = value

        self.clear_changes()

    def errors_for(self, field):
        if not self._errors.get(field):
            self._errors[field] = list()

        return self._errors[field].copy()

    def _add_error(self, field, msg):
        if not self._errors.get(field):
            self._errors[field] = list()

        if msg not in self._errors[field]:
            self._errors[field].append(msg)

    def validate_required(self, fields, msg="is required"):
        if isinstance(fields, str):
            fields = [fields]

        for field in fields:
            if not self.values.get(field):
                self._add_error(field, msg)

    def validate_base64(self, fields, msg="must be Base64 encoded"):
        if isinstance(fields, str):
            fields = [fields]

        for field in fields:
            value = self.values.get(field) or ""

            try:
                base64.b64decode(value, validate=True)
            except binascii.Error:
                self._add_error(field, msg)

    def validate_inclusion(self, field, data, msg="is invalid"):
        if self.values.get(field) not in data:
            self._add_error(field, msg)

    def validate_exclusion(self, field, data, msg="is invalid"):
        if self.values.get(field) in data:
            self._add_error(field, msg)

    def validate_subset(self, field, data, msg="has an invalid entry"):
        value_as_set = set(self.values.get(field, set()))

        if len(value_as_set) == 0 or value_as_set.issubset(data):
            self._add_error(field, msg)

    def validate_length(self, field, min=None, max=None, msg=None):
        value = self.values.get(field)
        length = len(value) if value else 0
        element_type = "character" if isinstance(value, str) else "item"

        if min and length < min:
            self._add_error(field, msg or f"should be at least {length} {element_type}(s)")

        if max and length > max:
            self._add_error(field, msg or f"should be at most {length} {element_type}(s)")

    def validate_number(self, field, *expressions, msg=None):
        value = self.values.get(field)

        if not value:
            return

        for exp in expressions:
            if exp[0] == "<" and value >= exp[1]:
                self._add_error(field, msg or f"must be less than {exp[1]}")
            elif exp[0] == ">" and value <= exp[1]:
                self._add_error(field, msg or f"must be greater than {exp[1]}")
            elif exp[0] == "<=" and value > exp[1]:
                self._add_error(field, msg or f"must be less than or equal to {exp[1]}")
            elif exp[0] == ">=" and value < exp[1]:
                self._add_error(field, msg or f"must be greater than or equal to {exp[1]}")
            elif exp[0] == "==" and value != exp[1]:
                self._add_error(field, msg or f"must be equal to {exp[1]}")
            elif exp[0] == "!=" and value == exp[1]:
                self._add_error(field, msg or f"must not be equal to {exp[1]}")

    def validate_format(self, field, format, msg=None):
        value = self.values.get(field, "")

        if not re.fullmatch(format, value):
            self._add_error(field, msg or "does not have the correct format")

    @property
    def record_values(self):
        return MappingProxyType(self._record_values)

    @property
    def changes(self):
        return MappingProxyType(self._changes)

    @property
    def values(self):
        return MappingProxyType({**self.record_values, **self.changes})

    @property
    def errors(self):
        errors = {field: errors for field, errors in self._errors.items() if len(errors) > 0}
        return MappingProxyType(errors)

    @property
    def changes_valid(self):
        return len(self.errors) == 0
