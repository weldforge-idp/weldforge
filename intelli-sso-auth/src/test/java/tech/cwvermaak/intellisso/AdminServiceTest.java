@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    @Mock private RoleRepository roleRepository;
    @InjectMocks private AdminService adminService;

    @Test
    void createRole_positive() {
        RoleDto dto = RoleDto.builder().name("Admin").description("Full access").build();
        Role saved = Role.builder().id(1L).name("Admin").build();
        when(roleRepository.save(any(Role.class))).thenReturn(saved);

        Role result = adminService.createRole(dto);

        assertEquals(1L, result.getId());
        verify(roleRepository).save(any(Role.class));
    }

    @Test
    void createRole_negative_nullName() {
        RoleDto dto = RoleDto.builder().name(null).build();
        assertThrows(IllegalArgumentException.class, () -> adminService.createRole(dto));
    }

    // more tests for getAllRoles etc.
}