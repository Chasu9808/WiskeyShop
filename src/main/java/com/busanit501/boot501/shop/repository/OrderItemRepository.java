package com.busanit501.boot501.shop.repository;


import com.busanit501.boot501.shop.entity.OrderItem;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {

}