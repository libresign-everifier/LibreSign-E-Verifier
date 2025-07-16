import sys
import os
import requests
import fitz  # PyMuPDF
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QListWidget, QListWidgetItem, QFrame,
    QLineEdit, QMessageBox, QSplashScreen, QFileDialog, QDialog,
    QScrollArea, QInputDialog
)
from PyQt6.QtGui import QFont, QPixmap, QImage, QIcon  
from PyQt6.QtCore import Qt, QTimer


class LibreSingEverifier(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LibreSign E-Verify")
        self.setGeometry(100, 100, 1000, 600)
        self.initUI()


    def initUI(self):
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)

        # Sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background-color: #f7f9fa;")
        sidebar_layout = QVBoxLayout()
        sidebar.setLayout(sidebar_layout)

        # Sidebar buttons
        self.buttons = {
            "Home": self.show_home,
            "Verify Keys": self.verify_keys_dialog,
            "Share": self.share_dialog,
            "About": self.show_about
        }

        for name, action in self.buttons.items():
            btn = QPushButton(name)
            btn.setFixedHeight(40)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    text-align: left;
                    padding-left: 20px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #e1e8ed;
                }
            """)
            btn.clicked.connect(action)
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()

        # Main content area
        content = QWidget()
        content_layout = QVBoxLayout()
        content.setLayout(content_layout)

        # Header
        header = QLabel("LibreSign E-Verify")
        header.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #007ee5; padding: 20px 0;")
        content_layout.addWidget(header)

        # URL + Key input for PDF verification
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Paste PDF URL here...")
        self.url_input.setFixedHeight(30)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Paste verification key here...")
        self.key_input.setFixedHeight(30)
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)

        fetch_button = QPushButton("Verify and Sign PDF")
        fetch_button.setFixedHeight(35)
        fetch_button.setStyleSheet("background-color: #007ee5; color: white; font-weight: bold;")
        fetch_button.clicked.connect(self.verify_and_sign_pdf)

        content_layout.addWidget(self.url_input)
        content_layout.addWidget(self.key_input)
        content_layout.addWidget(fetch_button)

        # File list
        self.file_list = QListWidget()
        content_layout.addWidget(self.file_list)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(content)
        self.setCentralWidget(main_widget)

    def verify_and_sign_pdf(self):
        
        import fitz  # PyMuPDF
        from datetime import datetime

        url = self.url_input.text().strip()
        key = self.key_input.text().strip()

        if not url or not key:
            QMessageBox.warning(self, "Input Error", "Please provide both a URL and a key.")
            return

        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.content

            filename = os.path.basename(url)
            if not filename.lower().endswith(".pdf"):
                filename += ".pdf"

            with open(filename, "wb") as f:
                f.write(data)

            doc = fitz.open(filename)

            # Create dialog
            sign_dialog = QDialog(self)
            sign_dialog.setWindowTitle("PDF Viewer and Signer")
            sign_dialog.resize(800, 600)

            # Scrollable area
            scroll_area = QScrollArea(sign_dialog)
            scroll_area.setWidgetResizable(True)

            content_widget = QWidget()
            content_layout = QVBoxLayout(content_widget)

            # Sign button at top
            sign_button = QPushButton("Sign this PDF as Read")
            sign_button.setStyleSheet("background-color: green; color: white; font-weight: bold;")
            content_layout.addWidget(sign_button, alignment=Qt.AlignmentFlag.AlignCenter)

            # Add page previews
            for page in doc:
                pix = page.get_pixmap(dpi=100)
                fmt = QImage.Format.Format_RGBA8888 if pix.alpha else QImage.Format.Format_RGB888
                img = QImage(pix.samples, pix.width, pix.height, pix.stride, fmt)
                if img.isNull():
                    continue

                label = QLabel()
                label.setPixmap(QPixmap.fromImage(img).scaledToWidth(700, Qt.TransformationMode.SmoothTransformation))
                label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                content_layout.addWidget(label)

            scroll_area.setWidget(content_widget)

            # Layout for the dialog
            dialog_layout = QVBoxLayout(sign_dialog)
            dialog_layout.addWidget(scroll_area)
            sign_dialog.setLayout(dialog_layout)

            def sign_all_pages():
                name, ok = QInputDialog.getText(self, "Sign PDF", "Enter your name for the signature:")
                if not ok or not name.strip():
                    return

                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                signature_text = f"Signed by: {name.strip()} on {now}"

                for page in doc:
                    # Add vertical (rotated) text on right edge of each page
                    page_width = page.rect.width
                    page_height = page.rect.height
                    rect = fitz.Rect(page_width - 40, 100, page_width - 10, page_height - 100)

                    page.insert_textbox(
                        rect,
                        signature_text,
                        fontsize=14,
                        fontname="helv",
                        rotate=90,
                        color=(0, 0, 0)
                    )
                    
                signed_filename = f"signed_{filename}"
                doc.save(signed_filename)
                doc.close()

                QMessageBox.information(self, "Signed", f"PDF saved as '{signed_filename}' with signatures on every page.")
                self.file_list.addItem(QListWidgetItem(f"Signed: {signed_filename}"))
                sign_dialog.close()

            sign_button.clicked.connect(sign_all_pages)
            sign_dialog.exec()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"PDF verification failed: {e}")

    def show_home(self):
        QMessageBox.information(self, "Home", "Welcome to LibreSign E-Verify.")

    def verify_keys_dialog(self):
        # Work In Progress. A mock right now, working only in Dev-branch
        dialog = QDialog(self)
        dialog.setWindowTitle("Verify Keys")
        layout = QVBoxLayout(dialog)

        domain_input = QLineEdit()
        domain_input.setPlaceholderText("Enter domain (e.g. example.com)")
        domain_input.setFixedHeight(30)

        check_button = QPushButton("Public Key")
        check_button.setStyleSheet("background-color: #007ee5; color: white; font-weight: bold;")
        check_button.setFixedHeight(35)

        layout.addWidget(domain_input)
        layout.addWidget(check_button)

        def show_key():
            domain = domain_input.text().strip()
            if not domain:
                QMessageBox.warning(dialog, "Input Error", "Please enter a domain.")
                return

            build_key = f"""-----BEGIN PUBLIC KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE3F7RYi8fUQqK
...
RjBGRs0=
-----END PUBLIC KEY-----"""
            QMessageBox.information(dialog, f"Public Key for {domain}", build_key)

        check_button.clicked.connect(show_key)
        dialog.setLayout(layout)
        dialog.exec()

    def share_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Share File")
        layout = QVBoxLayout(dialog)

        self.share_file_path = None

        file_button = QPushButton("Choose File")
        file_button.setFixedHeight(30)
        file_label = QLabel("(no file selected)")
        file_label.setWordWrap(True)

        file_button.clicked.connect(lambda: self.select_file(file_label))

        url_input = QLineEdit()
        url_input.setPlaceholderText("Enter destination URL")
        url_input.setFixedHeight(30)

        password_input = QLineEdit()
        password_input.setPlaceholderText("Enter password")
        password_input.setFixedHeight(30)
        password_input.setEchoMode(QLineEdit.EchoMode.Password)

        share_button = QPushButton("Share Now")
        share_button.setFixedHeight(35)
        share_button.setStyleSheet("background-color: #007ee5; color: white; font-weight: bold;")

        def share_now():
            url = url_input.text().strip()
            password = password_input.text().strip()

            if not self.share_file_path or not url or not password:
                QMessageBox.warning(dialog, "Missing Data", "Please complete all fields.")
                return

            try:
                print("Attempting to upload:", self.share_file_path)
                with open(self.share_file_path, 'rb') as file_data:
                    files = {'file': (os.path.basename(self.share_file_path), file_data)}
                    data = {'password': password}

                    response = requests.post(url, files=files, data=data)
                    response.raise_for_status()

                    self.file_list.addItem(QListWidgetItem(f"Shared: {os.path.basename(self.share_file_path)}"))
                    QMessageBox.information(dialog, "Success", f"File shared successfully to {url}")

            except requests.exceptions.RequestException as e:
                QMessageBox.critical(dialog, "Upload Failed", f"Error while sharing file:\n{str(e)}")
            except Exception as ex:
                QMessageBox.critical(dialog, "Unexpected Error", f"{str(ex)}")

        share_button.clicked.connect(share_now)

        layout.addWidget(file_button)
        layout.addWidget(file_label)
        layout.addWidget(url_input)
        layout.addWidget(password_input)
        layout.addWidget(share_button)

        dialog.setLayout(layout)
        dialog.exec()


    def select_file(self, label):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Share")
        if file_path:
            self.share_file_path = file_path
            label.setText(file_path)

    def show_about(self):
        about_text = (
            "LibreSign E-Verify\n"
            "Version 1.2.0.23\n"
            "Created with ❤️ by LibreSign Community\n\n"
        )
        QMessageBox.information(self, "About", about_text)


def show_main_window():
    global main_window
    main_window = LibreSingEverifier()
    main_window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("static/logo.ico")) 
    # Splash Screen
    splash = QSplashScreen()
    splash.setPixmap(QPixmap("static/logo.png"))  # Optional: add a logo pixmap
    splash.setFont(QFont("Arial", 16))
    splash.showMessage("Loading...", Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom, Qt.GlobalColor.black)
    splash.show()

    QTimer.singleShot(2000, lambda: (splash.close(), show_main_window()))
    sys.exit(app.exec())
