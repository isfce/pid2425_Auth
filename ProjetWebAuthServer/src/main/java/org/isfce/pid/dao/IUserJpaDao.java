package org.isfce.pid.dao;

import org.isfce.pid.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IUserJpaDao extends JpaRepository<User, String> {

}
