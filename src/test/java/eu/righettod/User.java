package eu.righettod;

import java.io.Serializable;
import java.util.Date;

public class User implements Serializable {
    private final String login;
    private final Date lastLogin;

    public User(Date lastLogin, String login) {
        this.lastLogin = lastLogin;
        this.login = login;
    }

    @Override
    public String toString() {
        return "User{" +
                "lastLogin=" + lastLogin +
                ", login='" + login + '\'' +
                '}';
    }
}
