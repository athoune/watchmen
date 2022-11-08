class CSVFile():
    def __init__(self, f):
        self.file = f

    def add_line(self, *line):
        l = len(line)
        for i, col in enumerate(line):
            self.file.write(str(col))
            if i < l - 1:
                self.file.write("\t")
        self.file.write("\n")
