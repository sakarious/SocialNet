import { Entity, BaseEntity, Column, PrimaryGeneratedColumn, CreateDateColumn } from "typeorm";

@Entity('users')
export class Users extends BaseEntity {

    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    fullname: string;

    @Column()
    password: string;

    @Column({
        unique: true
    })
    email: string

    @CreateDateColumn()
    created_on: Date

    @Column({
        default: 0,
        width:10
    })
    loginCount: number;

    @Column({
        default: 0,
        length: 200000
    })
    lockTime: string;
}