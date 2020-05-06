import hashlib
import json


class Singleton(object):
    _instance = None

    def __new__(_class, *args, **kwargs):
        if not isinstance(_class._instance, _class):
            _class._instance = object.__new__(_class, *args, **kwargs)
        return _class._instance


class Field(object):
    def __init__(self, field_name, field_type, **kwargs):
        self.name = field_name
        self.type = field_type
        self.required = False
        self.filterable = False
        if kwargs is not None:
            self.required = kwargs.get('required', False)
            self.filterable = kwargs.get('filterable', False)

    def get_field_name(self):
        return self.name

    def get_schema(self):
        return (self.name, self.type)

    def is_required(self):
        return self.required

    def is_filterable(self):
        return self.filterable


class BaseSchema(Singleton):
    def __init__(self):
        self.table_name = None
        self.fields = []

    def register_fields(self, fields_list):
        self.fields = list(zip(range(len(fields_list)), fields_list))

    def get_table_name(self):
        return self.table_name

    def get_columns(self):
        ''' returns a list of column names '''
        return [field.get_field_name() for col_id, field in self.fields]

    def get_required_column_ids(self):
        ''' returns a list of required column ids, zero-indexed '''
        return [
            col_id for col_id, field in self.fields if field.is_required()
        ]

    def get_filterable_column_ids(self):
        ''' returns a list of filterable column ids, zero-indexed '''
        return [
            col_id for col_id, field in self.fields if field.is_filterable()
        ]

    def get_schema(self):
        ''' returns a list of tuples of column name and sqlite types '''
        ''' sqlite type choices {NULL, INTEGER, REAL, TEXT, BLOB} '''
        return [field.get_schema() for col_id, field in self.fields]

    def get_create_table_sql(self):
        if not self.table_name:
            return
        col_list = []
        cols = self.get_schema()
        for col in cols:
            col_list.append(' '.join(col))
        col_schema = ','.join(col_list)
        sql = 'CREATE TABLE {} ({})'.format(
            self.table_name, col_schema
        )
        return sql

    def get_nested(self, var, nested_keys):
        curr = var
        for key in nested_keys:
            if key in curr:
                curr = curr[key]
            else:
                return None
        return curr

    def dedupe(self, rows):
        ''' deduplicate data rows that are exactly the same '''
        keys = {}
        output = []
        for row in rows:
            dedupe_key = hashlib.sha256(
                json.dumps(row).encode('utf-8')
            ).hexdigest()
            if dedupe_key not in keys:
                output.append(row)
                keys[dedupe_key] = True
        return output

    def get_data(self, constraints={}):
        ''' call API and extract data from response '''
        pass
