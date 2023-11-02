class ModelError(Exception):
    pass


class SchemaInvalid(ModelError):
    pass


class QueryInvalid(ModelError):
    pass


class ModelFieldError(Exception):
    pass


class UndefinedField(ModelFieldError):
    pass


class FieldDefinitionInvalid(ModelFieldError):
    pass


class FieldValueInvalid(ModelFieldError):
    pass


class FieldNonNullable(FieldValueInvalid):
    pass


class FieldTypeMismatch(FieldValueInvalid):
    pass


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


class StorageManagerError(Exception):
    pass


class BackendMissing(StorageManagerError):
    pass
