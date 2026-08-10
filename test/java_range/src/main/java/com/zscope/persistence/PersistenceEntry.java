package com.zscope.persistence;

import jakarta.persistence.EntityManager;
import org.bson.Document;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

public class PersistenceEntry {
    public ResultSet jdbcSearch(Statement statement, String name) throws SQLException {
        return statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public ResultSet jdbcConcatenatedSql(Statement statement, String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return statement.executeQuery(sql);
    }

    public ResultSet jdbcFakePrepared(Connection connection, String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        PreparedStatement statement = connection.prepareStatement(sql);
        return statement.executeQuery();
    }

    public List<?> jpaSearch(EntityManager entityManager, String name) {
        return entityManager.createQuery("from User u where u.name = '" + name + "'").getResultList();
    }

    public Document nosqlSearch(String rawJson) {
        return Document.parse("{\"name\":\"" + rawJson + "\"}");
    }

    public Object jndiLookup(String lookupName) throws NamingException {
        Context context = new InitialContext();
        return context.lookup(lookupName);
    }

    public Object ldapSearch(DirContext dirContext, String uid) throws NamingException {
        SearchControls controls = new SearchControls();
        return dirContext.search("ou=users", "(uid=" + uid + ")", controls);
    }

    public Object userLookup(String username) {
        return selectUserByUsername(username);
    }

    private Object selectUserByUsername(String username) {
        return username;
    }
}
