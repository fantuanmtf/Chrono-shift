#include "MainWindow.h"
#include "ContactList.h"
#include "ChatWidget.h"
#include "SettingsWidget.h"
#include "TitleBar.h"
#include "LoginWindow.h"
#include <QShowEvent>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_isSettingsOpen(false)
{
    setupUi();
    setupAnimations();
    applyTheme();
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUi()
{
    setWindowFlags(Qt::FramelessWindowHint);
    setMinimumSize(900, 600);
    resize(1100, 700);
    setAttribute(Qt::WA_Hover);

    m_mainStack = new QStackedWidget(this);
    setCentralWidget(m_mainStack);

    m_mainContent = new QWidget();
    m_mainLayout = new QHBoxLayout(m_mainContent);
    m_mainLayout->setContentsMargins(0, 0, 0, 0);
    m_mainLayout->setSpacing(0);

    m_contactList = new ContactList();
    m_chatWidget = new ChatWidget();
    m_settingsWidget = new SettingsWidget();

    m_titleBar = new TitleBar();
    m_titleBar->setMoveTarget(this);

    QWidget* rightPanel = new QWidget();
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);
    rightLayout->addWidget(m_titleBar);
    rightLayout->addWidget(m_chatWidget, 1);

    m_mainLayout->addWidget(m_contactList);
    m_mainLayout->addWidget(rightPanel, 1);

    m_mainStack->addWidget(m_mainContent);

    connect(m_contactList, &ContactList::contactSelected,
            this, &MainWindow::onContactSelected);
    connect(m_contactList, &ContactList::settingsClicked,
            this, &MainWindow::onSettingsClicked);
    connect(m_settingsWidget, &SettingsWidget::backClicked,
            this, &MainWindow::onBackFromSettings);
    connect(m_titleBar, &TitleBar::minimizeClicked,
            this, &MainWindow::onMinimize);
    connect(m_titleBar, &TitleBar::maximizeClicked,
            this, &MainWindow::onMaximize);
    connect(m_titleBar, &TitleBar::closeClicked,
            this, &MainWindow::onClose);
}

void MainWindow::setupAnimations()
{
}

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QMainWindow::resizeEvent(event);
    applyRoundedMask();
}

void MainWindow::showEvent(QShowEvent* event)
{
    QMainWindow::showEvent(event);
    applyRoundedMask();
}

void MainWindow::applyRoundedMask()
{
    if (isMaximized()) {
        clearMask();
        return;
    }
    const int radius = 16;
    QPainterPath path;
    path.addRoundedRect(rect(), radius, radius);
    setMask(path.toFillPolygon().toPolygon());
}

void MainWindow::applyTheme()
{
    setStyleSheet(R"(
        QWidget {
            background-color: #0f0f14;
            color: #ffffff;
        }
        QScrollBar:vertical {
            width: 6px;
            background: #1a1a24;
            border-radius: 3px;
        }
        QScrollBar::handle:vertical {
            background: #3a3a4a;
            border-radius: 3px;
            min-height: 30px;
        }
        QScrollBar::handle:vertical:hover {
            background: #4a4a5a;
        }
        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            height: 0;
        }
    )");
}

void MainWindow::onContactSelected(const QString& contactId)
{
    m_chatWidget->loadChat(contactId);
}

void MainWindow::onSettingsClicked()
{
    if (m_isSettingsOpen) return;
    m_isSettingsOpen = true;

    m_mainLayout->replaceWidget(m_contactList, m_settingsWidget);
    m_contactList->hide();
    m_settingsWidget->show();
}

void MainWindow::onBackFromSettings()
{
    if (!m_isSettingsOpen) return;
    m_isSettingsOpen = false;

    m_mainLayout->replaceWidget(m_settingsWidget, m_contactList);
    m_settingsWidget->hide();
    m_contactList->show();
}

void MainWindow::onMinimize()
{
    showMinimized();
}

void MainWindow::onMaximize()
{
    if (isMaximized()) {
        showNormal();
    } else {
        showMaximized();
    }
}

void MainWindow::onClose()
{
    close();
}

void MainWindow::showLogin()
{
    LoginWindow* login = new LoginWindow();
    connect(login, &LoginWindow::loginSuccess, this, [this]() {
        showMain();
    });
    login->show();
}

void MainWindow::showMain()
{
    show();
}