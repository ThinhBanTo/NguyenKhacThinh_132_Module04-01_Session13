package com.example.productservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @PostMapping
    public ResponseEntity<String> createProduct(
            @RequestHeader(value = "X-User-Id", required = false) String userId,
            @RequestHeader(value = "X-User-Role", required = false) String userRole
    ) {
        if ("ADMIN".equalsIgnoreCase(userRole)) {
            return ResponseEntity.ok("Tao san pham thanh cong boi user: " + userId);
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body("Forbidden: Only ADMIN can perform this action");
    }
}
