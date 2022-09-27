package org.data.auth.registration;

import org.data.auth.user.User;
import org.data.auth.user.UserRole;
import org.data.auth.user.UserService;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {

    private final UserService userService;

    private final EmailValidator emailValidator;

    public RegistrationService(UserService userService, EmailValidator emailValidator) {
        this.userService = userService;
        this.emailValidator = emailValidator;
    }

    public String register(RegistrationRequest request) {
        boolean isValidEmail = emailValidator.
                test(request.getEmail());
        if (!isValidEmail) {
            throw new IllegalStateException("email not valid");
        }
        return userService.signUpUser(
                new User(
                        request.getUsername(),
                        request.getEmail(),
                        request.getPassword(),
                        UserRole.USER
                )
        );
    }
}
