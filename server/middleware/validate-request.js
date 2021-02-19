export default function validateRequest(req: any, next: any, schema: any) {
    const options = {
        abortEarly: false, // include all errors
        allowUnknown: true, // ignore unknown props
        stripUnknown: true // remove unknown props
    };
    const { error, value } = schema.validate({...req.body, ...req.params }, options);
    if (error) {
        next(`Validation error: ${error.details.map((x: { message: any; }) => x.message).join(', ')}`);
    } else {
        req.body = value;
        next();
    }
}