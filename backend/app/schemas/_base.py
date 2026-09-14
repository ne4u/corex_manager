from pydantic import BaseModel, create_model


def _optional_update[T: BaseModel](base: type[T]) -> type[T]:
    """Return a new model based on `base` with all fields made Optional."""
    fields = {}
    for field_name, field_info in base.model_fields.items():
        annotation = field_info.annotation | None
        default = None if field_info.is_required() else field_info.default
        fields[field_name] = (annotation, default)
    return create_model(
        base.__name__.replace("Base", "Update"),
        __base__=base,
        __module__=__name__,
        **fields,
    )
