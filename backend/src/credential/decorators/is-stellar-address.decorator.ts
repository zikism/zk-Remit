import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

@ValidatorConstraint({ async: false })
export class IsStellarAddressConstraint implements ValidatorConstraintInterface {
  validate(value: any) {
    if (typeof value !== 'string') return false;
    return /^G[A-Z2-7]{55}$/.test(value);
  }

  defaultMessage(args: ValidationArguments) {
    return `${args.property} must be a valid Stellar G-address (56 chars starting with G)`;
  }
}

export function IsStellarAddress(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsStellarAddressConstraint,
    });
  };
}
