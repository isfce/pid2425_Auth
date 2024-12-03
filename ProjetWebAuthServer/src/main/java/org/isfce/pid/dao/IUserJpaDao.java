package org.isfce.pid.dao;

import java.util.Optional;

import org.isfce.pid.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IUserJpaDao extends JpaRepository<User, String> {
	//User findByUsername(String username);
	Optional<String> getEmailByUsername(String username);
}
