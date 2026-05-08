#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QHBoxLayout>
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>
#include <QResizeEvent>
#include <QPainterPath>
#include <QRegion>

class ContactList;
class ChatWidget;
class SettingsWidget;
class TitleBar;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void showLogin();
    void showMain();

private slots:
    void onContactSelected(const QString& contactId);
    void onSettingsClicked();
    void onBackFromSettings();
    void onMinimize();
    void onMaximize();
    void onClose();

private:
    void setupUi();
    void setupAnimations();
    void applyTheme();
    void applyRoundedMask();

protected:
    void resizeEvent(QResizeEvent* event) override;
    void showEvent(QShowEvent* event) override;

    QStackedWidget* m_mainStack;
    QWidget* m_mainContent;
    QHBoxLayout* m_mainLayout;

    ContactList* m_contactList;
    ChatWidget* m_chatWidget;
    SettingsWidget* m_settingsWidget;
    TitleBar* m_titleBar;

    QPropertyAnimation* m_slideAnimation;
    bool m_isSettingsOpen;
};

#endif // MAINWINDOW_H