using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.Foundation.Metadata;

public class DesempenhoAnalyzer
{
    delegate void AnaliseDesempenho(SyntaxTree syntaxTree, Dictionary<string, int[]> findings);

    public async Task<StringBuilder> AnalyzeCodeAsync(SyntaxTree syntaxTree)
    {
        AnaliseDesempenho[] analisesDesempenho =
        {
            AnalyzeUnnecessaryObjectCreation,
            AnalyzeInefficientDataStructures,
            AnalyzeLackOfInputValidation,
            AnalyzeExcessiveUseOfExceptions,
            AnalyzeInefficientStringConcatenation,
            AnalyzeNotDisposingOfResources,
            AnalyzeNotUsinghronousProgramming,
            AnalyzeNotCachingData
        };

        // Create a list to store the findings
        var findings = new Dictionary<string, int[]>();

        // Analyze the code for each pattern
        List<Task> tasks = new List<Task>();

        for(int i = 0; i < analisesDesempenho.Count(); i++)
        {
            tasks.Add(Task.Run(() => analisesDesempenho[i](syntaxTree,findings)));
        }

        await Task.WhenAll(tasks);

        // Save the findings to an HTML table
        StringBuilder table = new StringBuilder(null);

        if (findings.Count() <= 0)
        {
            return await Task.FromResult(table);
        }

        table.AppendLine("<table>");
        table.AppendLine("<tr><th>Pattern Name</th><th>Line Numbers</th></tr>");
        table.AppendLine("<tr>");

        foreach (var finding in findings)
        {
            table.Append($"<td>{finding.Key}</td><td>");

            for (int i = 0; i < finding.Value.Count(); i++)
            {
                table.Append($"{finding.Value[i]}");

                if (i + 1 < finding.Value.Count())
                {
                    table.Append(',');
                }
            }

            table.Append("</td></tr>");
        }

        table.AppendLine("</table>");

        return await Task.FromResult(table);
    }

    void AnalyzeUnnecessaryObjectCreation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var objectCreationExpressions = syntaxTree.GetRoot().DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        foreach (var expression in objectCreationExpressions)
        {
            if (IsUnnecessaryObjectCreation(expression))
            {
                findings["Unnecessary object creation"] = findings.TryGetValue("Unnecessary object creation", out var lines)
                ? lines.Concat(new[] { expression.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { expression.GetLocation().GetLineSpan().StartLinePosition.Line +1 };
            }
        }
    }
    void AnalyzeInefficientDataStructures(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var dataStructureDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<VariableDeclarationSyntax>();
        foreach (var declaration in dataStructureDeclarations)
        {
            if (IsInefficientDataStructure(declaration))
            {
                findings["Inefficient data structure"] = findings.TryGetValue("Inefficient data structure", out var lines)
                ? lines.Concat(new[] { declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeLackOfInputValidation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsLackOfInputValidation(method))
            {
               findings["Lack of input validation"] = findings.TryGetValue("Lack of input validation", out var lines)
               ? lines.Concat(new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeExcessiveUseOfExceptions(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var throwStatements = syntaxTree.GetRoot().DescendantNodes().OfType<ThrowStatementSyntax>();
        foreach (var statement in throwStatements)
        {
            if (IsExcessiveUseOfExceptions(statement))
            {
               findings["Excessive use of exceptions"] = findings.TryGetValue("Excessive use of exceptions", out var lines)
               ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeInefficientStringConcatenation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var stringConcatenations = syntaxTree.GetRoot().DescendantNodes().OfType<InterpolatedStringContentSyntax>();
        foreach (var concatenation in stringConcatenations)
        {
            if (IsInefficientStringConcatenation(concatenation))
            {
               findings["Inefficient string concatenation"] = findings.TryGetValue("Inefficient string concatenation", out var lines)
               ? lines.Concat(new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeNotDisposingOfResources(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var usingStatements = syntaxTree.GetRoot().DescendantNodes().OfType<UsingStatementSyntax>();
        foreach (var statement in usingStatements)
        {
            if (IsNotDisposingOfResources(statement))
            {
              findings["Not disposing of resources"] = findings.TryGetValue("Not disposing of resources", out var lines)
              ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
              : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeNotUsinghronousProgramming(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsNotUsingAsynchronousProgramming(method))
            {
                findings["Not using hronous programming"] = new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line };
            }
        }
    }
    void AnalyzeNotCachingData(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var compilation = CSharpCompilation.Create("DesempenhoAnalyzer");
        var semanticModel = compilation.GetSemanticModel(syntaxTree);

        var methodInvocations = syntaxTree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in methodInvocations)
        {
            if (IsNotCachingData(invocation, semanticModel))
            {
                findings["Not caching data"] = new[] { invocation.GetLocation().GetLineSpan().StartLinePosition.Line };
            }
        }
    }

    bool IsUnnecessaryObjectCreation(ObjectCreationExpressionSyntax expression)
    {
        // Verificar se o objeto criado é imediatamente atribuído a uma variável
        if (expression.Parent is AssignmentExpressionSyntax assignment)
        {
            var variable = assignment.Left as IdentifierNameSyntax;
            if (variable != null)
            {
                // Verificar se a variável é usada apenas uma vez
                var usages = expression.SyntaxTree.GetRoot().DescendantNodes().OfType<IdentifierNameSyntax>()
                   .Where(id => id.Identifier.ValueText == variable.Identifier.ValueText);
                if (usages.Count() == 1)
                {
                    return true; // Criação de objeto desnecessária
                }
            }
        }

        // Verificar se o objeto criado é passado como parâmetro para um método
        if (expression.Parent is ArgumentSyntax argument)
        {
            var methodCall = argument.Parent as InvocationExpressionSyntax;
            if (methodCall != null)
            {
                // Verificar se o método não armazena o objeto criado em lugar algum
                var methodSymbol = methodCall.Expression as IdentifierNameSyntax;
                if (methodSymbol != null && methodSymbol.Identifier.ValueText == "MethodName")
                {
                    return true; // Criação de objeto desnecessária
                }
            }
        }

        return false; // Criação de objeto necessária
    }
    bool IsInefficientDataStructure(VariableDeclarationSyntax declaration)
    {
        var initializer = declaration.Parent as EqualsValueClauseSyntax;
        if (initializer != null)
        {
            var objectCreation = initializer.Parent as ObjectCreationExpressionSyntax;
            if (objectCreation != null)
            {
                var type = objectCreation.Type;
                if (type is IdentifierNameSyntax identifierName)
                {
                    var typeName = identifierName.Identifier.ValueText;
                    // Check if the type is an inefficient data structure
                    switch (typeName)
                    {
                        case "ArrayList":
                        case "Hashtable":
                        case "Queue":
                        case "Stack":
                        case "ConcurrentDictionary":
                            // These are considered inefficient data structures
                            return true;
                        default:
                            // Other types are not considered inefficient
                            return false;
                    }
                }
            }
        }
        return false;
    }
    bool IsLackOfInputValidation(MethodDeclarationSyntax method)
    {
        // Verificar se o método tem parâmetros
        if (method.ParameterList.Parameters.Count == 0)
        {
            return false; // Se não tiver parâmetros, não há input para validar
        }

        // Verificar se há alguma lógica de validação de entrada no corpo do método
        var methodBody = method.Body;
        if (methodBody == null)
        {
            return true; // Se o método não tiver corpo, assume-se que não há validação de entrada
        }

        // Verificar se há chamadas a métodos de validação de entrada (e.g. string.IsNullOrEmpty, int.TryParse, etc.)
        var validationMethods = new[] { "string.IsNullOrEmpty", "int.TryParse", "long.TryParse", "bool.TryParse", "double.TryParse", "DateTime.TryParse" };
        var validationCalls = methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>()
           .Where(i => validationMethods.Contains(i.Expression.ToString()));
        if (validationCalls.Any())
        {
            return false; // Se há chamadas a métodos de validação de entrada, assume-se que há validação de entrada
        }

        // Verificar se há verificações de condição (e.g. if (input == null) {... })
        var conditionals = methodBody.DescendantNodes().OfType<IfStatementSyntax>();
        foreach (var conditional in conditionals)
        {
            var condition = conditional.Condition;
            if (condition is BinaryExpressionSyntax binaryExpression)
            {
                var left = binaryExpression.Left;
                var right = binaryExpression.Right;
                if (left is IdentifierNameSyntax identifier && identifier.Identifier.Text == "input" &&
                    right is LiteralExpressionSyntax literal && literal.Token.ValueText == "null")
                {
                    return false; // Se há uma verificação de condição que checa se o input é nulo, assume-se que há validação de entrada
                }
            }
        }

        // Se não há nenhuma lógica de validação de entrada, retorna true
        return true;
    }
    bool IsExcessiveUseOfExceptions(ThrowStatementSyntax statement)
    {
        var parent = statement.Parent;
        while (parent != null)
        {
            if (parent is TryStatementSyntax)
            {
                var tryBlock = (TryStatementSyntax)parent;
                if (tryBlock.Catches.Count == 0 && tryBlock.Block.Statements.Count == 1 && tryBlock.Block.Statements[0] == statement)
                {
                    var expression = statement.Expression;
                    TypeSyntax exceptionType = null;
                    
                    if (expression is ObjectCreationExpressionSyntax objectCreation)
                    {
                        exceptionType = objectCreation.Type;
                    }
                    else if (expression is IdentifierNameSyntax identifierName)
                    {
                        exceptionType = identifierName;
                    }
                    
                    if (exceptionType != null)
                    {
                        var typeName = exceptionType.ToString();
                        if (typeName == "Exception" || typeName == "ApplicationException")
                        {
                            return true;
                        }
                    }
                }
                break;
            }
            parent = parent.Parent;
        }
        return false;
    }
    bool IsInefficientStringConcatenation(InterpolatedStringContentSyntax concatenation)
    {
        // Verificar se a concatenação ocorre dentro de um loop
        var parent = concatenation.Parent;
        while (parent != null)
        {
            if (parent is ForStatementSyntax || parent is WhileStatementSyntax || parent is DoStatementSyntax)
            {
                return true;
            }
            parent = parent.Parent;
        }

        // Verificar se a concatenação envolve muitas operações de concatenação
        var expressions = concatenation.DescendantNodes().OfType<BinaryExpressionSyntax>();
        var concatenationCount = 0;
        foreach (var expression in expressions)
        {
            if (expression.OperatorToken.IsKind(SyntaxKind.PlusToken))
            {
                concatenationCount++;
            }
        }
        return concatenationCount >3; // ajuste o valor de acordo com a sua necessidade
    }
    bool IsNotDisposingOfResources(UsingStatementSyntax usingStatement)
    {
        return true;
    }


    private bool IsNotUsingAsynchronousProgramming(MethodDeclarationSyntax method)
    {
        return true;
    }

    // Check if an invocation expression is not caching data
    private bool IsNotCachingData(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        return true;
    }
}