#include "SettingsWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSpacerItem>
#include <QGroupBox>
#include <QApplication>

SettingsWidget::SettingsWidget(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
}

SettingsWidget::~SettingsWidget()
{
}

void SettingsWidget::setupUi()
{
    setFixedWidth(280);
    setStyleSheet(R"(
        QWidget {
            background: #15151f;
            border-right: 1px solid rgba(255, 255, 255, 0.05);
        }
    )");

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(20);

    QHBoxLayout* headerLayout = new QHBoxLayout();

    m_backBtn = new QPushButton();
    m_backBtn->setFixedSize(36, 36);
    m_backBtn->setText("←");
    m_backBtn->setStyleSheet(R"(
        QPushButton {
            background: rgba(255, 255, 255, 0.06);
            border: none;
            border-radius: 8px;
            font-size: 16px;
            color: #ffffff;
        }
        QPushButton:hover {
            background: rgba(255, 255, 255, 0.12);
        }
    )");
    connect(m_backBtn, &QPushButton::clicked, this, &SettingsWidget::onBackClicked);
    headerLayout->addWidget(m_backBtn);

    QLabel* titleLabel = new QLabel("Settings");
    titleLabel->setStyleSheet(R"(
        QLabel {
            font-size: 18px;
            font-weight: 600;
            color: #ffffff;
        }
    )");
    headerLayout->addWidget(titleLabel);
    headerLayout->addSpacerItem(new QSpacerItem(20, 20, QSizePolicy::Expanding));

    layout->addLayout(headerLayout);

    QString groupStyle = R"(
        QGroupBox {
            font-size: 12px;
            font-weight: 600;
            color: #8888aa;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            margin-top: 6px;
            padding-top: 14px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px 0 6px;
        }
    )";

    QString checkStyle = R"(
        QCheckBox {
            font-size: 13px;
            color: #ffffff;
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 20px;
            height: 20px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.08);
            border: 2px solid rgba(255, 255, 255, 0.15);
        }
        QCheckBox::indicator:hover {
            border-color: rgba(255, 255, 255, 0.3);
        }
        QCheckBox::indicator:checked {
            background: #6366f1;
            border-color: #6366f1;
        }
    )";

    QGroupBox* generalGroup = new QGroupBox("GENERAL");
    generalGroup->setStyleSheet(groupStyle);
    QVBoxLayout* generalLayout = new QVBoxLayout(generalGroup);
    generalLayout->setContentsMargins(12, 16, 12, 12);
    generalLayout->setSpacing(10);

    m_darkThemeCheck = new QCheckBox("Dark Theme");
    m_darkThemeCheck->setChecked(true);
    m_darkThemeCheck->setStyleSheet(checkStyle);
    connect(m_darkThemeCheck, &QCheckBox::toggled, this, &SettingsWidget::onThemeToggle);
    generalLayout->addWidget(m_darkThemeCheck);

    m_notificationsCheck = new QCheckBox("Notifications");
    m_notificationsCheck->setChecked(true);
    m_notificationsCheck->setStyleSheet(checkStyle);
    generalLayout->addWidget(m_notificationsCheck);

    m_autoConnectCheck = new QCheckBox("Auto Connect");
    m_autoConnectCheck->setChecked(false);
    m_autoConnectCheck->setStyleSheet(checkStyle);
    generalLayout->addWidget(m_autoConnectCheck);

    layout->addWidget(generalGroup);

    QGroupBox* networkGroup = new QGroupBox("NETWORK");
    networkGroup->setStyleSheet(groupStyle);
    QVBoxLayout* networkLayout = new QVBoxLayout(networkGroup);
    networkLayout->setContentsMargins(12, 16, 12, 12);
    networkLayout->setSpacing(10);

    QString editStyle = R"(
        QLineEdit {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 8px 10px;
            font-size: 13px;
            color: #ffffff;
        }
        QLineEdit:focus {
            border-color: #6366f1;
        }
    )";

    {
        QHBoxLayout* row = new QHBoxLayout();
        QLabel* lbl = new QLabel("Host:");
        lbl->setStyleSheet("font-size: 13px; color: #8888aa;");
        row->addWidget(lbl);
        m_hostEdit = new QLineEdit("127.0.0.1");
        m_hostEdit->setStyleSheet(editStyle);
        row->addWidget(m_hostEdit, 1);
        networkLayout->addLayout(row);
    }

    {
        QHBoxLayout* row = new QHBoxLayout();
        QLabel* lbl = new QLabel("Port:");
        lbl->setStyleSheet("font-size: 13px; color: #8888aa;");
        row->addWidget(lbl);
        m_portEdit = new QLineEdit("4443");
        m_portEdit->setStyleSheet(editStyle);
        row->addWidget(m_portEdit, 1);
        networkLayout->addLayout(row);
    }

    layout->addWidget(networkGroup);

    QGroupBox* appearanceGroup = new QGroupBox("APPEARANCE");
    appearanceGroup->setStyleSheet(groupStyle);
    QVBoxLayout* appearanceLayout = new QVBoxLayout(appearanceGroup);
    appearanceLayout->setContentsMargins(12, 16, 12, 12);
    appearanceLayout->setSpacing(10);

    QHBoxLayout* fontSizeHeader = new QHBoxLayout();
    QLabel* fontSizeLabel = new QLabel("Font Size");
    fontSizeLabel->setStyleSheet("font-size: 13px; color: #ffffff;");
    fontSizeHeader->addWidget(fontSizeLabel);
    fontSizeHeader->addSpacerItem(new QSpacerItem(20, 20, QSizePolicy::Expanding));

    m_fontSizeLabel = new QLabel("14px");
    m_fontSizeLabel->setStyleSheet("font-size: 13px; color: #6366f1;");
    fontSizeHeader->addWidget(m_fontSizeLabel);
    appearanceLayout->addLayout(fontSizeHeader);

    m_fontSizeSlider = new QSlider(Qt::Horizontal);
    m_fontSizeSlider->setRange(10, 20);
    m_fontSizeSlider->setValue(14);
    m_fontSizeSlider->setStyleSheet(R"(
        QSlider::groove:horizontal {
            height: 5px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 2px;
        }
        QSlider::handle:horizontal {
            width: 16px;
            height: 16px;
            background: #6366f1;
            border-radius: 8px;
            margin: -6px 0;
        }
        QSlider::handle:horizontal:hover {
            background: #818cf8;
        }
    )");
    connect(m_fontSizeSlider, &QSlider::valueChanged, [this](int value) {
        m_fontSizeLabel->setText(QString("%1px").arg(value));
        QFont font = QApplication::font();
        font.setPixelSize(value);
        QApplication::setFont(font);
        if (parentWidget()) {
            parentWidget()->update();
        }
    });
    appearanceLayout->addWidget(m_fontSizeSlider);

    layout->addWidget(appearanceGroup);
    layout->addSpacerItem(new QSpacerItem(20, 20, QSizePolicy::Expanding));

    m_saveBtn = new QPushButton("Save Changes");
    m_saveBtn->setStyleSheet(R"(
        QPushButton {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #6366f1,stop:1 #8b5cf6);
            border: none;
            border-radius: 12px;
            padding: 12px;
            font-size: 14px;
            font-weight: 600;
            color: #ffffff;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #4f46e5,stop:1 #7c3aed);
        }
    )");
    connect(m_saveBtn, &QPushButton::clicked, this, &SettingsWidget::onSaveClicked);
    layout->addWidget(m_saveBtn);
}

void SettingsWidget::onBackClicked()
{
    emit backClicked();
}

void SettingsWidget::onThemeToggle(bool checked)
{
    emit themeChanged(checked);
}

void SettingsWidget::onSaveClicked()
{
    emit backClicked();
}