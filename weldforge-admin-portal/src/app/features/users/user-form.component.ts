import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { UserService } from '../../core/services/user.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-user-form',
  templateUrl: './user-form.component.html',
  styleUrls: ['./user-form.component.css'],
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule]
})
export class UserFormComponent implements OnInit {
  userForm!: FormGroup;
  isEditMode = false;
  userId: string | null = null;

  constructor(
    private fb: FormBuilder,
    private userService: UserService,
    private router: Router,
    private route: ActivatedRoute
  ) { }

  ngOnInit(): void {
    this.userId = this.route.snapshot.paramMap.get('id');
    this.isEditMode = !!this.userId;

    this.userForm = this.fb.group({
      username: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      firstName: [''],
      lastName: [''],
      enabled: [true],
      password: ['']
    });

    if (this.isEditMode && this.userId) {
      this.userService.getUser(this.userId).subscribe(user => {
        this.userForm.patchValue(user);
      });
    } else {
        this.userForm.get('password')?.setValidators(Validators.required);
    }
  }

  onSubmit(): void {
    if (this.userForm.invalid) {
      return;
    }

    const userData = this.userForm.value;

    if (this.isEditMode && this.userId) {
      if (!userData.password) {
        delete userData.password;
      }
      this.userService.updateUser(this.userId, userData).subscribe(() => {
        this.router.navigate(['/users']);
      });
    } else {
      this.userService.createUser(userData).subscribe(() => {
        this.router.navigate(['/users']);
      });
    }
  }

  onCancel(): void {
    this.router.navigate(['/users']);
  }
}