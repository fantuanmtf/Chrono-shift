#include "TitleBar.h"
#include <QWindow>

TitleBar::TitleBar(QWidget *parent)
    : QWidget(parent), m_moveTarget(nullptr)
{
    setupUi();
}

TitleBar::~TitleBar()
{
}

void TitleBar::setMoveTarget(QWidget* target)
{
    m_moveTarget = target;
}

void TitleBar::setupUi()
{
    setFixedHeight(38);
    setCursor(Qt::ArrowCursor);
    setStyleSheet(R"(
        QWidget {
            background: #1a1a24;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
    )");

    QHBoxLayout* layout = new QHBoxLayout(this);
    layout->setContentsMargins(12, 0, 8, 0);
    layout->setSpacing(8);

    m_titleLabel = new QLabel("Chrono-shift");
    m_titleLabel->setStyleSheet(R"(
        QLabel {
            font-size: 13px;
            font-weight: 600;
            color: #ffffff;
            padding-left: 4px;
        }
    )");
    layout->addWidget(m_titleLabel);
    layout->addSpacerItem(new QSpacerItem(20, 20, QSizePolicy::Expanding));

    m_minimizeBtn = new QPushButton();
    m_minimizeBtn->setFixedSize(36, 28);
    m_minimizeBtn->setText("─");
    m_minimizeBtn->setCursor(Qt::ArrowCursor);
    m_minimizeBtn->setStyleSheet(R"(
        QPushButton {
            background: transparent;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            color: #aaaaaa;
        }
        QPushButton:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
        }
    )");
    connect(m_minimizeBtn, &QPushButton::clicked, this, &TitleBar::minimizeClicked);
    layout->addWidget(m_minimizeBtn);

    m_maximizeBtn = new QPushButton();
    m_maximizeBtn->setFixedSize(36, 28);
    m_maximizeBtn->setText("□");
    m_maximizeBtn->setCursor(Qt::ArrowCursor);
    m_maximizeBtn->setStyleSheet(R"(
        QPushButton {
            background: transparent;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            color: #aaaaaa;
        }
        QPushButton:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
        }
    )");
    connect(m_maximizeBtn, &QPushButton::clicked, this, &TitleBar::maximizeClicked);
    layout->addWidget(m_maximizeBtn);

    m_closeBtn = new QPushButton();
    m_closeBtn->setFixedSize(36, 28);
    m_closeBtn->setText("✕");
    m_closeBtn->setCursor(Qt::ArrowCursor);
    m_closeBtn->setStyleSheet(R"(
        QPushButton {
            background: transparent;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            color: #aaaaaa;
        }
        QPushButton:hover {
            background: #ef4444;
            color: #ffffff;
        }
    )");
    connect(m_closeBtn, &QPushButton::clicked, this, &TitleBar::closeClicked);
    layout->addWidget(m_closeBtn);
}

void TitleBar::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton) {
        QWidget* target = m_moveTarget ? m_moveTarget : window();
        if (target->windowHandle()) {
            target->windowHandle()->startSystemMove();
        }
    }
    QWidget::mousePressEvent(event);
}

void TitleBar::mouseDoubleClickEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton) {
        emit maximizeClicked();
    }
    QWidget::mouseDoubleClickEvent(event);
}