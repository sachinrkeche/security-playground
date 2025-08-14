package com.spring.securityplayground;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.util.Arrays;

@SpringBootApplication
public class SecurityPlaygroundApplication {

	@Autowired
	ApplicationContext context;

	public static void main(String[] args) {
		SpringApplication.run(SecurityPlaygroundApplication.class, args);
	}

	@PostConstruct
	public void checkBeans() {
		System.out.println("Beans: " + Arrays.toString(context.getBeanDefinitionNames()));
	}
}
