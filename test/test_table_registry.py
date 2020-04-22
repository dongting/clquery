from unittest import TestCase
from unittest.mock import patch

import clquery.table_registry
import clquery.schema


class ChildSchema(clquery.schema.BaseSchema):
    def __init__(self):
        self.var = 't1'


class MetaClass(object):
    child_schema = ChildSchema
    base_schema = clquery.schema.BaseSchema


class MockClassOne(object):
    pass


class MockClassTwo(object):
    @classmethod
    def get_table_name(cls):
        return 't2'


class MockClassThree(object):
    @classmethod
    def get_table_name(cls):
        return 't3'


class TestTableRegistry(TestCase):
    @patch('clquery.table_registry.registry', [MetaClass])
    def test_get_tables(self):
        tables = clquery.table_registry.get_tables()

        self.assertEqual(len(tables), 1)
        self.assertEqual(tables[0].var, 't1')

    @patch('clquery.table_registry.get_tables')
    def test_get_obj_by_table_name(self, mock_tables):
        mock_tables.return_value = [
            MockClassOne, MockClassTwo, MockClassThree
        ]

        obj = clquery.table_registry.get_obj_by_table_name('t3')
        self.assertEqual(obj.get_table_name(), 't3')

