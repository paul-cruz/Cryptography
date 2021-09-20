import sys
from design import Ui_MainWindow
from PyQt5 import QtWidgets


class Window(QtWidgets.QMainWindow):

    def __init__(self):
        super(Window, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.btnCalculate.clicked.connect(self.calculate_functions)

    def calculate_functions(self):
        dialog = QtWidgets.QMessageBox
        try:
            n = int(self.ui.txtN.text())
            beta = int(self.ui.txtBeta.text())
            alpha = int(self.ui.txtAlpha.text())

            beta = beta % n

            if not self.validate_alpha(alpha, n):
                dialog.about(self, "Alpha Error",
                             "Alpha's value is invalid, enter its value again")
                return

            _, alpha_reciprocal, _ = self.extended_eucledian_algorithm(
                n, alpha)

            beta_opposite = n - beta

            self.ui.lblEncrypt.setText(f"C = {alpha} p + {beta} mod {n}")
            self.ui.lblDecrypt.setText(
                f"C = {alpha_reciprocal} [C + ({beta_opposite})] mod {n}")

        except Exception as e:
            print(e)
            dialog.about(self, "Unknown error", e)

    def validate_alpha(self, alpha: int, n: int) -> bool:
        if alpha > n:
            return False

        dividend, divisor = n, alpha
        mod = dividend % divisor

        while mod != 0:
            dividend, divisor = divisor, mod
            mod = dividend % divisor

        return divisor == 1

    def extended_eucledian_algorithm(self, a: int, b: int):
        if a == 0:
            return b, 0, 1

        gcd, x1, y1 = self.extended_eucledian_algorithm(b % a, a)

        x = y1 - (b//a) * x1
        y = x1

        return gcd, x, y


app = QtWidgets.QApplication([])

application = Window()

application.show()

sys.exit(app.exec())
