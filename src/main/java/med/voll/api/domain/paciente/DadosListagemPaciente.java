package med.voll.api.domain.paciente;

public record DadosListagemPaciente(Long id, String name, String email, String cpf) {

    public DadosListagemPaciente(Paciente paciente){
        this(paciente.getId(), paciente.getNome(), paciente.getEmail(), paciente.getCpf());
    }
}
