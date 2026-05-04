package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import tech.cwvermaak.weldforge.model.BackupCode;

import java.util.List;

public interface BackupCodeRepository extends JpaRepository<BackupCode, Long> {

    List<BackupCode> findByUserIdAndUsedAtIsNull(Long userId);

    long countByUserIdAndUsedAtIsNull(Long userId);

    @Modifying
    @Query("delete from BackupCode b where b.user.id = :userId")
    void deleteAllByUserId(Long userId);
}
