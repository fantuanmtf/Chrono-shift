#include "ContactList.h"
#include <QVBoxLayout>
#include <QListWidgetItem>
#include <QMouseEvent>

ContactList::ContactList(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    populateContacts();
}

ContactList::~ContactList()
{
}

void ContactList::setupUi()
{
    setFixedWidth(280);
    setStyleSheet(R"(
        QWidget {
            background: #15151f;
            border-right: 1px solid rgba(255, 255, 255, 0.05);
        }
    )");

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(10);

    QWidget* headerWidget = new QWidget();
    headerWidget->setFixedHeight(44);
    QHBoxLayout* headerLayout = new QHBoxLayout(headerWidget);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    m_searchEdit = new QLineEdit();
    m_searchEdit->setPlaceholderText("Search...");
    m_searchEdit->setStyleSheet(R"(
        QLineEdit {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 8px 12px;
            font-size: 13px;
            color: #ffffff;
        }
        QLineEdit:focus {
            border-color: #6366f1;
            background: rgba(99, 102, 241, 0.1);
        }
    )");
    connect(m_searchEdit, &QLineEdit::textChanged, this, &ContactList::onSearchTextChanged);
    headerLayout->addWidget(m_searchEdit, 1);

    m_settingsBtn = new QPushButton();
    m_settingsBtn->setFixedSize(36, 36);
    m_settingsBtn->setText("⚙");
    m_settingsBtn->setStyleSheet(R"(
        QPushButton {
            background: rgba(255, 255, 255, 0.06);
            border: none;
            border-radius: 8px;
            font-size: 16px;
        }
        QPushButton:hover {
            background: rgba(255, 255, 255, 0.12);
        }
    )");
    connect(m_settingsBtn, &QPushButton::clicked, this, &ContactList::onSettingsBtnClicked);
    headerLayout->addWidget(m_settingsBtn);

    layout->addWidget(headerWidget);

    m_contactList = new QListWidget();
    m_contactList->setStyleSheet(R"(
        QListWidget {
            background: transparent;
            border: none;
            outline: none;
        }
        QListWidget::item {
            padding: 0px;
            border-radius: 8px;
            margin-bottom: 4px;
        }
        QListWidget::item:hover {
            background: rgba(255, 255, 255, 0.06);
        }
        QListWidget::item:selected {
            background: rgba(99, 102, 241, 0.15);
        }
    )");
    m_contactList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_contactList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_contactList->setSelectionMode(QAbstractItemView::SingleSelection);

    m_contactList->viewport()->installEventFilter(this);

    connect(m_contactList, &QListWidget::itemClicked, this, &ContactList::onContactClicked);

    layout->addWidget(m_contactList);
}

bool ContactList::eventFilter(QObject* obj, QEvent* event)
{
    if (obj == m_contactList->viewport() && event->type() == QEvent::MouseButtonPress) {
        QMouseEvent* me = static_cast<QMouseEvent*>(event);
        QListWidgetItem* item = m_contactList->itemAt(me->pos());
        if (item) {
            m_contactList->setCurrentItem(item);
            onContactClicked(item);
        }
    }
    return QWidget::eventFilter(obj, event);
}

void ContactList::populateContacts()
{
    struct Contact {
        QString id;
        QString name;
        QString status;
        bool online;
    };

    QList<Contact> contacts = {
        {"1", "Alice Smith", "Hey! How are you?", true},
        {"2", "Bob Johnson", "Let me check...", true},
        {"3", "Charlie Brown", "See you tomorrow!", false},
        {"4", "David Davis", "Sounds good!", true},
        {"5", "Eve Wilson", "OK, I'll be there", false},
        {"6", "Frank Miller", "New message!", true},
        {"7", "Grace Taylor", "Thanks!", false},
        {"8", "Henry Anderson", "Got it!", true},
    };

    for (const Contact& c : contacts) {
        QListWidgetItem* item = new QListWidgetItem(m_contactList);
        item->setData(Qt::UserRole, c.id);

        QWidget* widget = new QWidget();
        widget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        widget->setFixedHeight(60);

        QHBoxLayout* layout = new QHBoxLayout(widget);
        layout->setContentsMargins(8, 8, 8, 8);
        layout->setSpacing(12);

        QWidget* avatarContainer = new QWidget();
        avatarContainer->setFixedSize(44, 44);

        QLabel* avatar = new QLabel(avatarContainer);
        avatar->setFixedSize(44, 44);
        avatar->setAlignment(Qt::AlignCenter);
        avatar->setText(QString(c.name[0]));
        avatar->setStyleSheet(R"(
            QLabel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
                border-radius: 22px;
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
            }
        )");
        avatar->move(0, 0);

        QLabel* statusDot = new QLabel(avatarContainer);
        statusDot->setFixedSize(10, 10);
        statusDot->setStyleSheet(c.online ?
            "QLabel { background: #22c55e; border-radius: 5px; border: 2px solid #15151f; }" :
            "QLabel { background: #6b7280; border-radius: 5px; border: 2px solid #15151f; }");
        statusDot->move(34, 34);

        layout->addWidget(avatarContainer);

        QWidget* infoWidget = new QWidget();
        infoWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        QVBoxLayout* infoLayout = new QVBoxLayout(infoWidget);
        infoLayout->setContentsMargins(0, 4, 0, 4);
        infoLayout->setSpacing(2);

        QLabel* nameLabel = new QLabel(c.name);
        nameLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        nameLabel->setStyleSheet("QLabel { font-size: 14px; font-weight: 600; color: #ffffff; }");
        nameLabel->setWordWrap(false);
        infoLayout->addWidget(nameLabel);

        QLabel* statusLabel = new QLabel(c.status);
        statusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        statusLabel->setStyleSheet("QLabel { font-size: 12px; color: #8888aa; }");
        statusLabel->setWordWrap(false);
        infoLayout->addWidget(statusLabel);

        layout->addWidget(infoWidget, 1);

        item->setSizeHint(QSize(0, 60));
        m_contactList->setItemWidget(item, widget);
    }
}

void ContactList::onContactClicked(QListWidgetItem* item)
{
    if (!item) return;
    QString contactId = item->data(Qt::UserRole).toString();
    emit contactSelected(contactId);
}

void ContactList::onSearchTextChanged(const QString& text)
{
    for (int i = 0; i < m_contactList->count(); ++i) {
        QListWidgetItem* item = m_contactList->item(i);
        QWidget* widget = m_contactList->itemWidget(item);
        bool match = false;
        if (widget) {
            QList<QLabel*> labels = widget->findChildren<QLabel*>();
            for (QLabel* label : labels) {
                if (label->text().contains(text, Qt::CaseInsensitive)) {
                    match = true;
                    break;
                }
            }
        }
        if (!match) {
            match = item->data(Qt::UserRole).toString().contains(text, Qt::CaseInsensitive);
        }
        item->setHidden(!match);
    }
}

void ContactList::onSettingsBtnClicked()
{
    emit settingsClicked();
}