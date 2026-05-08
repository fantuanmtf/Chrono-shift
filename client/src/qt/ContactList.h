#ifndef CONTACTLIST_H
#define CONTACTLIST_H

#include <QWidget>
#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QPropertyAnimation>
#include <QLabel>
#include <QSizePolicy>
#include <QEvent>

class ContactList : public QWidget
{
    Q_OBJECT

public:
    explicit ContactList(QWidget *parent = nullptr);
    ~ContactList();

signals:
    void contactSelected(const QString& contactId);
    void settingsClicked();

private slots:
    void onContactClicked(QListWidgetItem* item);
    void onSearchTextChanged(const QString& text);
    void onSettingsBtnClicked();

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void setupUi();
    void populateContacts();

    QListWidget* m_contactList;
    QLineEdit* m_searchEdit;
    QPushButton* m_settingsBtn;
};

#endif // CONTACTLIST_H