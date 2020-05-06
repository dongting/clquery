import json
import apsw

from . import table_registry


class CloudModule(object):
    def __init__(self, conn):
        self.conn = conn

    def Create(self, conn, modulename, dbname, table_name, *args):
        col_schema = ','.join(list(args))
        sql_schema = 'CREATE TABLE {} ({});'.format(table_name, col_schema)
        table_obj = table_registry.get_obj_by_table_name(table_name)
        return sql_schema, CloudTable(self.conn, table_name, table_obj)

    Connect = Create


class CloudTable(object):
    def __init__(self, conn, table_name, table_obj):
        self.conn = conn
        self.table_name = table_name
        self.table_obj = table_obj

    def BestIndex(self, constraints, orderbys):
        ''' Return in constraints the required params for the table
            schema, so that Filter/xFilter function can receive the
            constraint values and generate the underlying data
            accordingly. Everything else can still be constrained but
            we'll let sqlite take care of those.
        '''
        interested_column_ids = self.table_obj.get_required_column_ids() \
            + self.table_obj.get_filterable_column_ids()

        col_map = {}  # maps str(constraint col id) to real col id
        constraint_index = 0
        constraints_resp = []
        for col_id, constraint_operator in constraints:
            # only handle SQLITE_INDEX_CONSTRAINT_EQ constraints for now
            # because other most likely will not translate into aws api
            # constraints, so we will just let sqlite handle those
            if col_id in interested_column_ids and \
                    constraint_operator == apsw.SQLITE_INDEX_CONSTRAINT_EQ:
                constraints_resp.append(constraint_index)
                col_map[str(constraint_index)] = col_id
                constraint_index += 1
            else:
                constraints_resp.append(None)
        return (
            tuple(constraints_resp),
            0,  # not used
            json.dumps(col_map),
            False,  # let sqlite handle all ordering
            1000  # not currently used
        )

    def Disconnect(self):
        pass

    Destroy = Disconnect

    def Open(self):
        return CloudCursor(self)

    def _readonly(self, *args):
        raise apsw.exceptionfor(apsw.SQLITE_READONLY)

    Rename = UpdateChangeRow = UpdateDeleteRow = UpdateInsertRow = _readonly


class CloudCursor(object):
    def __init__(self, cloud_table):
        ''' Note that the data is kept here in Cursor, instead of
            Table. This allows us to show a different view of the
            table for each cursor that is pointing to the same
            'table'.
            For example, a query to list all files with a required arg
            of a pre-specified s3 bucket name, would allow us to show
            multiple buckets collectively at the same time, each
            cursor viewing a potentially different bucket.
        '''
        self.table = cloud_table

    def Close(self):
        pass

    def Column(self, number):
        ''' if number is -1, then return rowid
            note that in sqlite, rowid col is at -1,
            and in both sqlite and our implementation col 0 is a real
            col (not rowid col)
        '''
        if number == -1:
            return self.cursor + 1
        else:
            return self.data[self.cursor][number]

    def Eof(self):
        return self.cursor >= self.len

    def Filter(self, indexnum, indexname, constraintargs):
        # sqlite rowids start at 1
        # our data's cursor starts at 0
        # clquery> select * from ...
        # where region='west-1' and region='west-2' and region='east-1'
        # {"0": 3, "1": 3, "2": 3}
        # ('west-1', 'west-2', 'east-1')

        constraints = {}
        multi_equals_check = {}
        col_map = json.loads(indexname)
        col_map_len = len(col_map.keys())
        columns = self.table.table_obj.get_columns()
        required_cols = self.table.table_obj.get_required_column_ids()
        for i in range(col_map_len):
            multi_equals_key = str(col_map[str(i)])
            multi_equals_val = multi_equals_check.get(
                multi_equals_key, None
            )
            if multi_equals_val is not None and \
                    multi_equals_val != constraintargs[i]:
                # there are multiple Equal constraints on the same key
                # but with different values.
                # This doesn't make sense, so error
                raise apsw.ConstraintError
            multi_equals_check[multi_equals_key] = constraintargs[i]
            constraints[columns[col_map[str(i)]]] = constraintargs[i]

        # make sure all required columns are present
        for required_col in required_cols:
            if str(required_col) not in col_map:
                raise apsw.ConstraintError('Required field not used.')

        self.data = self.table.table_obj.get_data(
            constraints=constraints
        )

        self.len = len(self.data)
        self.cursor = 0

    def Next(self):
        self.cursor += 1

    def Rowid(self):
        return self.cursor + 1
