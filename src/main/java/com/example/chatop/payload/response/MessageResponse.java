package com.example.chatop.payload.response;



public class MessageResponse {
    private String message;
    private int code;

    public MessageResponse(String message) {
        this.message = message;
    }


    public int getCode() {
        return code;
    }
    public String getMessage() {
        return message;
    }

    public void setCode(int c) {
        this.code = c;
    }
    public void setMessage(String message) {
        this.message = message;
    }
}
