#include "ChatWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollBar>
#include <QTimer>

ChatWidget::ChatWidget(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
}

ChatWidget::~ChatWidget()
{
}

void ChatWidget::setupUi()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    m_chatHeader = new QWidget();
    m_chatHeader->setFixedHeight(48);
    m_chatHeader->setStyleSheet("background: #12121a; border-bottom: 1px solid rgba(255,255,255,0.05);");
    QHBoxLayout* headerLayout = new QHBoxLayout(m_chatHeader);
    headerLayout->setContentsMargins(16, 0, 16, 0);

    m_chatTitle = new QLabel("Select a contact");
    m_chatTitle->setStyleSheet("font-size: 15px; font-weight: 600; color: #ffffff; background: transparent;");
    headerLayout->addWidget(m_chatTitle);
    layout->addWidget(m_chatHeader);

    m_messagesArea = new QScrollArea();
    m_messagesArea->setWidgetResizable(true);
    m_messagesArea->setStyleSheet(R"(
        QScrollArea { background: #0f0f14; border: none; }
    )");
    m_messagesArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    m_messagesContainer = new QWidget();
    m_messagesLayout = new QVBoxLayout(m_messagesContainer);
    m_messagesLayout->setContentsMargins(16, 16, 16, 16);
    m_messagesLayout->setSpacing(12);
    m_messagesLayout->addStretch();

    m_messagesArea->setWidget(m_messagesContainer);
    layout->addWidget(m_messagesArea, 1);

    QWidget* inputWidget = new QWidget();
    inputWidget->setStyleSheet("background: #15151f; border-top: 1px solid rgba(255,255,255,0.05);");

    QHBoxLayout* inputLayout = new QHBoxLayout(inputWidget);
    inputLayout->setContentsMargins(12, 10, 12, 10);
    inputLayout->setSpacing(10);

    m_messageEdit = new QLineEdit();
    m_messageEdit->setPlaceholderText("Type a message...");
    m_messageEdit->setStyleSheet(R"(
        QLineEdit {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 10px 16px;
            font-size: 14px;
            color: #ffffff;
        }
        QLineEdit:focus {
            border-color: #6366f1;
            background: rgba(99,102,241,0.1);
        }
    )");
    connect(m_messageEdit, &QLineEdit::returnPressed, this, &ChatWidget::onSendClicked);
    inputLayout->addWidget(m_messageEdit, 1);

    m_sendBtn = new QPushButton();
    m_sendBtn->setFixedSize(40, 40);
    m_sendBtn->setText("↑");
    m_sendBtn->setStyleSheet(R"(
        QPushButton {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #6366f1,stop:1 #8b5cf6);
            border: none;
            border-radius: 20px;
            font-size: 18px;
            color: #ffffff;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #4f46e5,stop:1 #7c3aed);
        }
        QPushButton:disabled {
            background: #3a3a4a;
            color: #666666;
        }
    )");
    connect(m_sendBtn, &QPushButton::clicked, this, &ChatWidget::onSendClicked);
    inputLayout->addWidget(m_sendBtn);

    layout->addWidget(inputWidget);
}

void ChatWidget::loadChat(const QString& contactId)
{
    m_currentContactId = contactId;

    QLayoutItem* item;
    while ((item = m_messagesLayout->takeAt(0)) != nullptr) {
        if (item->widget()) {
            delete item->widget();
        }
        delete item;
    }
    m_messagesLayout->addStretch();

    if (contactId == "1") {
        m_chatTitle->setText("Alice Smith");
        addMessage("Hey! How are you?", false);
        addMessage("I'm doing great, thanks for asking!", true);
        addMessage("What are you working on today?", false);
    } else if (contactId == "2") {
        m_chatTitle->setText("Bob Johnson");
        addMessage("Let me check the logs real quick...", false);
        addMessage("Sure, take your time.", true);
    } else if (contactId == "3") {
        m_chatTitle->setText("Charlie Brown");
        addMessage("See you tomorrow at the meeting!", false);
        addMessage("OK, I'll be there at 10.", true);
    } else if (contactId == "4") {
        m_chatTitle->setText("David Davis");
        addMessage("Sounds good! Let's do it.", false);
        addMessage("Great, I'll send the invite.", true);
    } else if (contactId == "5") {
        m_chatTitle->setText("Eve Wilson");
        addMessage("OK, I'll be there on time.", false);
        addMessage("Perfect, see you then!", true);
    } else if (contactId == "6") {
        m_chatTitle->setText("Frank Miller");
        addMessage("New message! Check this out.", false);
        addMessage("Wow, that looks amazing!", true);
    } else if (contactId == "7") {
        m_chatTitle->setText("Grace Taylor");
        addMessage("Thanks for your help yesterday!", false);
        addMessage("No problem at all!", true);
    } else if (contactId == "8") {
        m_chatTitle->setText("Henry Anderson");
        addMessage("Got it! I'll handle it.", false);
        addMessage("Thanks Henry!", true);
    } else {
        m_chatTitle->setText("Unknown Contact");
    }
}

void ChatWidget::addMessage(const QString& text, bool isSent)
{
    QWidget* messageWidget = new QWidget();
    QHBoxLayout* messageLayout = new QHBoxLayout(messageWidget);
    messageLayout->setContentsMargins(0, 0, 0, 0);

    QWidget* bubble = new QWidget();
    QVBoxLayout* bubbleLayout = new QVBoxLayout(bubble);
    bubbleLayout->setContentsMargins(14, 10, 14, 10);
    bubbleLayout->setSpacing(4);

    QLabel* textLabel = new QLabel(text);
    textLabel->setWordWrap(true);
    textLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    textLabel->setStyleSheet(isSent
        ? "font-size: 14px; color: #ffffff; background: transparent;"
        : "font-size: 14px; color: #e5e5e5; background: transparent;");
    textLabel->setMaximumWidth(380);

    QLabel* timeLabel = new QLabel("Just now");
    timeLabel->setStyleSheet("font-size: 10px; color: #666677; background: transparent;");

    bubbleLayout->addWidget(textLabel);
    bubbleLayout->addWidget(timeLabel);

    if (isSent) {
        bubble->setStyleSheet(R"(
            QWidget {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #6366f1,stop:1 #8b5cf6);
                border-radius: 12px;
            }
        )");
        messageLayout->addSpacerItem(new QSpacerItem(60, 20, QSizePolicy::Expanding));
        messageLayout->addWidget(bubble, 0, Qt::AlignRight);
    } else {
        bubble->setStyleSheet(R"(
            QWidget {
                background: #1e1e28;
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 12px;
            }
        )");
        messageLayout->addWidget(bubble, 0, Qt::AlignLeft);
        messageLayout->addSpacerItem(new QSpacerItem(60, 20, QSizePolicy::Expanding));
    }

    int insertPos = m_messagesLayout->count() - 1;
    m_messagesLayout->insertWidget(insertPos, messageWidget);

    QTimer::singleShot(50, this, &ChatWidget::scrollToBottom);
}

void ChatWidget::onSendClicked()
{
    QString text = m_messageEdit->text().trimmed();
    if (text.isEmpty()) return;

    addMessage(text, true);
    m_messageEdit->clear();
}

void ChatWidget::scrollToBottom()
{
    QScrollBar* sb = m_messagesArea->verticalScrollBar();
    sb->setValue(sb->maximum());
}