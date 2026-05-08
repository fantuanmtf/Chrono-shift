#include "LoginWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QSpacerItem>
#include <QGraphicsDropShadowEffect>
#include <QTimer>

LoginWindow::LoginWindow(QWidget *parent)
    : QDialog(parent)
{
    setupUi();
    setupAnimations();
    applyGlassEffect();
}

LoginWindow::~LoginWindow()
{
}

void LoginWindow::setupUi()
{
    setWindowFlags(Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    resize(420, 520);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    QWidget* glassWidget = new QWidget();
    glassWidget->setObjectName("glassWidget");
    glassWidget->setStyleSheet(R"(
        #glassWidget {
            background: rgba(25, 25, 35, 0.85);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
    )");

    QGraphicsBlurEffect* blur = new QGraphicsBlurEffect(this);
    blur->setBlurRadius(20);
    glassWidget->setGraphicsEffect(blur);

    QVBoxLayout* layout = new QVBoxLayout(glassWidget);
    layout->setContentsMargins(40, 50, 40, 50);
    layout->setSpacing(20);

    QLabel* titleLabel = new QLabel("Chrono-shift");
    titleLabel->setStyleSheet(R"(
        QLabel {
            font-size: 32px;
            font-weight: 700;
            color: #ffffff;
            text-align: center;
        }
    )");
    layout->addWidget(titleLabel, 0, Qt::AlignCenter);

    QLabel* subtitleLabel = new QLabel("Secure Messenger");
    subtitleLabel->setStyleSheet(R"(
        QLabel {
            font-size: 14px;
            color: #8888aa;
            text-align: center;
        }
    )");
    layout->addWidget(subtitleLabel, 0, Qt::AlignCenter);

    layout->addSpacerItem(new QSpacerItem(20, 40));

    QLabel* userLabel = new QLabel("Username");
    userLabel->setStyleSheet(R"(
        QLabel {
            font-size: 13px;
            color: #aaaaaa;
            margin-bottom: 8px;
        }
    )");
    layout->addWidget(userLabel);

    m_usernameEdit = new QLineEdit();
    m_usernameEdit->setPlaceholderText("Enter your username");
    m_usernameEdit->setStyleSheet(R"(
        QLineEdit {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 10px;
            padding: 14px 16px;
            font-size: 14px;
            color: #ffffff;
        }
        QLineEdit:focus {
            border-color: #6366f1;
            background: rgba(99, 102, 241, 0.1);
        }
        QLineEdit::placeholder {
            color: #555566;
        }
    )");
    layout->addWidget(m_usernameEdit);

    QHBoxLayout* passwordLayout = new QHBoxLayout();

    QLabel* passLabel = new QLabel("Password");
    passLabel->setStyleSheet(R"(
        QLabel {
            font-size: 13px;
            color: #aaaaaa;
            margin-bottom: 8px;
        }
    )");
    layout->addWidget(passLabel);

    m_passwordEdit = new QLineEdit();
    m_passwordEdit->setPlaceholderText("Enter your password");
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setStyleSheet(R"(
        QLineEdit {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 10px;
            padding: 14px 16px;
            font-size: 14px;
            color: #ffffff;
        }
        QLineEdit:focus {
            border-color: #6366f1;
            background: rgba(99, 102, 241, 0.1);
        }
    )");
    layout->addWidget(m_passwordEdit);

    m_passwordToggle = new QPushButton();
    m_passwordToggle->setFixedSize(32, 32);
    m_passwordToggle->setStyleSheet(R"(
        QPushButton {
            background: transparent;
            border: none;
            image: url(:/icons/eye_off.png);
        }
        QPushButton:hover {
            opacity: 0.7;
        }
    )");
    connect(m_passwordToggle, &QPushButton::clicked, this, &LoginWindow::onPasswordVisibilityToggle);

    layout->addSpacerItem(new QSpacerItem(20, 20));

    m_loginButton = new QPushButton("Login");
    m_loginButton->setStyleSheet(R"(
        QPushButton {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border: none;
            border-radius: 10px;
            padding: 14px;
            font-size: 15px;
            font-weight: 600;
            color: #ffffff;
        }
        QPushButton:hover {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
        }
        QPushButton:pressed {
            transform: translateY(0);
        }
    )");
    connect(m_loginButton, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
    layout->addWidget(m_loginButton);

    m_registerButton = new QPushButton("Create Account");
    m_registerButton->setStyleSheet(R"(
        QPushButton {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            padding: 14px;
            font-size: 14px;
            color: #ffffff;
        }
        QPushButton:hover {
            border-color: rgba(255, 255, 255, 0.4);
            background: rgba(255, 255, 255, 0.05);
        }
    )");
    connect(m_registerButton, &QPushButton::clicked, this, &LoginWindow::onRegisterClicked);
    layout->addWidget(m_registerButton);

    mainLayout->addWidget(glassWidget, 0, Qt::AlignCenter);
}

void LoginWindow::setupAnimations()
{
    m_fadeAnimation = new QPropertyAnimation(this, "windowOpacity");
    m_fadeAnimation->setDuration(300);
    m_fadeAnimation->setStartValue(0);
    m_fadeAnimation->setEndValue(1);
    m_fadeAnimation->start();

    m_slideAnimation = new QPropertyAnimation(this, "pos");
    m_slideAnimation->setDuration(400);
    m_slideAnimation->setEasingCurve(QEasingCurve::OutCubic);
}

void LoginWindow::applyGlassEffect()
{
    QGraphicsDropShadowEffect* shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(30);
    shadow->setColor(QColor(99, 102, 241, 50));
    shadow->setOffset(0, 10);
    findChild<QWidget*>("glassWidget")->setGraphicsEffect(shadow);
}

void LoginWindow::onLoginClicked()
{
    m_fadeAnimation->setDirection(QPropertyAnimation::Backward);
    m_fadeAnimation->start();

    QTimer::singleShot(300, this, [this]() {
        emit loginSuccess();
        close();
    });
}

void LoginWindow::onRegisterClicked()
{
}

void LoginWindow::onPasswordVisibilityToggle()
{
    if (m_passwordEdit->echoMode() == QLineEdit::Password) {
        m_passwordEdit->setEchoMode(QLineEdit::Normal);
        m_passwordToggle->setStyleSheet(R"(
            QPushButton {
                background: transparent;
                border: none;
                image: url(:/icons/eye.png);
            }
        )");
    } else {
        m_passwordEdit->setEchoMode(QLineEdit::Password);
        m_passwordToggle->setStyleSheet(R"(
            QPushButton {
                background: transparent;
                border: none;
                image: url(:/icons/eye_off.png);
            }
        )");
    }
}