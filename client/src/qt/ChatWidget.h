#ifndef CHATWIDGET_H
#define CHATWIDGET_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QLabel>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>

class ChatWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ChatWidget(QWidget *parent = nullptr);
    ~ChatWidget();

    void loadChat(const QString& contactId);

private slots:
    void onSendClicked();
    void scrollToBottom();

private:
    void setupUi();
    void addMessage(const QString& text, bool isSent);

    QWidget* m_chatHeader;
    QLabel* m_chatTitle;
    QScrollArea* m_messagesArea;
    QWidget* m_messagesContainer;
    QVBoxLayout* m_messagesLayout;
    QLineEdit* m_messageEdit;
    QPushButton* m_sendBtn;
    QString m_currentContactId;
};

#endif // CHATWIDGET_H