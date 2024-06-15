import idaapi, idautils, idc
from PyQt5 import QtCore, QtGui, QtWidgets

default_instructions = [
    'int3', 'lods', 'stos', 'scas', 'ins', 'rdtsc', 'rdtscp',
    'sysenter', 'sysexit', 'syscall', 'rep', 'repne', 'repe',
    'nop', 'ud2', 'cpuid', 'popf', 'xchg', 'cmpxchg', 'xadd',
    'xor', 'rol', 'ror', 'shl', 'shr', 'neg', 'sbb', 'cmp',
]

class CustomBreakPointPlugin(idaapi.PluginForm):
    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # Create a table widget
        self.table = QtWidgets.QTableWidget(len(default_instructions), 1)
        self.table.setHorizontalHeaderLabels(["Instructions"])
        self.table.horizontalHeader().setStretchLastSection(True)  # Stretch the instruction column to maximize width
        
        for index, instruction in enumerate(default_instructions):
            item = QtWidgets.QTableWidgetItem(instruction)
            self.table.setItem(index, 0, item)

        # Create input field for new instruction
        self.instruction_input = QtWidgets.QLineEdit()
        self.instruction_input.setPlaceholderText("Enter new instruction")
        self.instruction_input.returnPressed.connect(self.add_instruction)  # Add instruction on Enter key press

        # Create button to add new instruction
        self.add_instruction_btn = QtWidgets.QPushButton("Add Instruction")
        self.add_instruction_btn.clicked.connect(self.add_instruction)

        # Create button to delete selected instruction
        self.delete_instruction_btn = QtWidgets.QPushButton("Delete Selected")
        self.delete_instruction_btn.clicked.connect(self.delete_instruction)

        # Create set breakpoint button
        self.set_bp_btn = QtWidgets.QPushButton("Set Breakpoints")
        self.set_bp_btn.clicked.connect(self.set_breakpoints)

        # Add keyboard shortcuts
        self.add_instruction_shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Return"), self.parent)
        self.add_instruction_shortcut.activated.connect(self.add_instruction)

        self.delete_instruction_shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Delete"), self.parent)
        self.delete_instruction_shortcut.activated.connect(self.delete_instruction)

        layout.addWidget(self.table)
        layout.addWidget(self.instruction_input)
        layout.addWidget(self.add_instruction_btn)
        layout.addWidget(self.delete_instruction_btn)
        layout.addWidget(self.set_bp_btn)

        self.parent.setLayout(layout)

    def add_instruction(self):
        new_instruction = self.instruction_input.text().strip()
        if new_instruction:
            row_count = self.table.rowCount()
            self.table.insertRow(row_count)
            item = QtWidgets.QTableWidgetItem(new_instruction)
            self.table.setItem(row_count, 0, item)
            self.instruction_input.clear()

    def delete_instruction(self):
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())

        for row in sorted(selected_rows, reverse=True):
            self.table.removeRow(row)

    def set_breakpoints(self):
        selected_instructions = []
        # Iterate over table rows to find selected instructions
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None:  # Check if item exists
                selected_instructions.append(item.text())

        # Set breakpoints on selected instructions
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                for head in idautils.Heads(func_ea, func_end):
                    if idc.is_code(idc.get_full_flags(head)):
                        if idc.print_insn_mnem(head) in selected_instructions:
                            idaapi.add_bpt(head)
                            idaapi.disable_bpt(head)
                            print(f"[CBS] Breakpoint -> {hex(head)}: {idc.print_insn_mnem(head)}")
        
    def OnClose(self, form):
        pass

class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Set disabled breakpoints on specific instructions"
    help = "This plugin sets disabled breakpoints on specified instructions"
    wanted_name = "Custom Breakpoint Setter"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.form = CustomBreakPointPlugin()
        self.form.Show("Custom BreakPoint Plugin")
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

def PLUGIN_ENTRY():
    return MyPlugin()
