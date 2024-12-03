package org.isfce.pid.model;

import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity(name = "TUSER")
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED, force = true)
@ToString(exclude = "password")
@EqualsAndHashCode(exclude = "password")
@Getter
@Setter

public final class User implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(length = 50, nullable = false)
	private final String username; // identifiant
	
	@Column(unique = true,nullable = false)
	private final String email;

	// password crypté
	@Column(length = 100, nullable = false)
	private final String password;

	@Column(nullable = true)
	@Enumerated(EnumType.STRING)
	private final Roles role;
}
