using System.ComponentModel.DataAnnotations;

namespace API.Dtos;

public class RegisterDto
{
    [Required]
    [MaxLength(100)]
    public required string Username  { get; set; }
    public required string Password { get; set; }
}