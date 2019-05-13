package com.yubikey.demo;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class DataService {

    private final Map<Integer, UserModel> userStorage = new ConcurrentHashMap<>();

    public void addUser(UserModel userModel) {
        userStorage.put(userModel.getUserId(), userModel);
    }

}
