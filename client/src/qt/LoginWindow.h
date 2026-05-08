#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QPropertyAnimation>
#include <QGraphicsBlurEffect>

class LoginWindow : public QDialog
{
    Q_OBJECT

public:
    explicit LoginWindow(QWidget *parent = nullptr);
    ~LoginWindow();

signals:
    void loginSuccess();

private slots:
    void onLoginClicked();
    void onRegisterClicked();
    void onPasswordVisibilityToggle();

private:
    void setupUi();
    void setupAnimations();
    void applyGlassEffect();

    QLineEdit* m_usernameEdit;
    QLineEdit* m_passwordEdit;
    QPushButton* m_loginButton;
    QPushButton* m_registerButton;
    QPushButton* m_passwordToggle;

    QPropertyAnimation* m_fadeAnimation;
    QPropertyAnimation* m_slideAnimation;
};

#endif // LOGINWINDOW_H