import sys
import apsw
from tabulate import tabulate

from . import table_registry
from . import vtable


def setup():
    ''' This setups two sets of tables:
        1. the real tables that implement sqlite vtables and would
           make outbound network calls to fetch live results
        2. a cached version of each real table that contains the results
           from the last run. This allows further offline iteration.
           The name of the cached table is _ appended by the real name
    '''
    conn = apsw.Connection('')
    tables = table_registry.get_tables()
    cloud_module = vtable.CloudModule(conn)
    conn.createmodule('clquery_module', cloud_module)

    for table in tables:
        col_list = []
        cols = table.get_schema()
        for col in cols:
            col_list.append(' '.join(col))
        col_schema = ','.join(col_list)
        conn.cursor().execute(
            'CREATE VIRTUAL TABLE {} USING clquery_module({})'.format(
                table.get_table_name(), col_schema
            )
        )
        conn.cursor().execute(
            'CREATE VIRTUAL TABLE {} USING clquery_module({})'.format(
                '_' + table.get_table_name(), col_schema
            )
        )
    return conn


def interactive_mode():
    conn = setup()
    interactive = CliShell(db=conn)
    interactive.command_prompt([
        'clquery> ',
        '    ...> '
    ])
    interactive.process_command('.mode python')
    interactive.process_command('.headers on')
    interactive.cmdloop()


class PythonShell(apsw.Shell):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.output_buffer = []

    def output_python(self, header, line):
        if header:
            if not self.header:
                return
        self.output_buffer.append([l for l in line])

    def cmdloop(self, intro=''):
        super().cmdloop(intro)

    def process_complete_line(self, command):
        self.output_buffer = []
        # sys.stdout.flush()
        # sys.stdout.write('\r')
        sys.stdout.flush()
        sys.stdout.write('[querying...]')
        sys.stdout.flush()
        super().process_complete_line(command)
        sys.stdout.write('\r')
        sys.stdout.flush()
        self.emit_output(self.output_buffer)

    def emit_output(self, output):
        ''' This function needs to be implemented by the subclass'''
        return


class CliShell(PythonShell):
    def emit_output(self, output):
        if len(output) > 0:
            self.write(
                self.stdout,
                tabulate(
                    output,
                    headers='firstrow',
                    tablefmt='orgtbl',
                    missingval='NULL'
                ) + '\n'
            )
            self.write(
                self.stdout,
                '[{} rows returned]\n'.format(str(len(output) - 1))
            )
        else:
            self.write(
                self.stdout, '[0 rows returned]\n'
            )


if __name__ == '__main__':
    interactive_mode()
