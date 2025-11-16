package com.busanit501.boot501.shop.repository;

import com.busanit501.boot501.shop.entity.Order;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface OrderRepository extends JpaRepository<Order, Long> {

    @Query("select o from Order o " +
            "where o.member.mid = :mid " +
            "order by o.orderDate desc"
    )
    List<Order> findOrders(@Param("mid") String mid, Pageable pageable);

    @Query("select count(o) from Order o " +
            "where o.member.mid = :mid"
    )
    Long countOrder(@Param("mid") String mid);
}