import inspect

from . import schema
from . import tables_aws

registry = [
    tables_aws,
]


def get_tables():
    tables = []
    for elt in registry:
        for name, member in inspect.getmembers(elt, inspect.isclass):
            if issubclass(member, schema.BaseSchema) and \
                    member != schema.BaseSchema:
                tables.append(member())
    return tables


def get_obj_by_table_name(table_name):
    classes = get_tables()
    for elt_obj in classes:
        elt_fn = getattr(elt_obj, 'get_table_name', None)
        if elt_fn is None:
            continue
        elt_name = elt_fn()
        if elt_name and elt_name == table_name:
            return elt_obj
